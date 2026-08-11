from datetime import datetime, timedelta, timezone

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.scoring import _shared
from src.scoring.knobs import RelevanceKnobs
from src.scoring.relevance import score_entity

K = RelevanceKnobs.from_config()
NOW = datetime(2026, 7, 30, tzinfo=timezone.utc)


@pytest.fixture
def driver():
    d = get_driver()
    d.verify_connectivity()
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


def _score(driver, label="ThreatActor", key="apt-rel-test"):
    with driver.session() as s:
        return s.execute_write(
            lambda tx: score_entity(tx, label=label, key=key, knobs=K, now=NOW)
        )


def test_fr_es_06_centrality_reflects_assertion_degree_not_article_count(driver):
    """FR-ES-06: Given an entity mentioned in 1000 articles but with few assertion edges,
    When scored, Then its centrality reflects assertion-edge degree, not article count."""
    with driver.session() as s:
        s.run(
            "MERGE (a:ThreatActor {merge_key:'apt-rel-test'}) "
            "SET a.test_fixture = true, a.first_seen = $now "
            "WITH a UNWIND range(1, 50) AS i "
            "MERGE (art:Article {source_guid_key: 'src::' + toString(i)}) "
            "SET art.test_fixture = true "
            "MERGE (art)-[:MENTIONS]->(a)",
            now=NOW,
        ).consume()

    assert _score(driver).centrality == 0.0     # 50 mentions, zero assertion edges

    with driver.session() as s:
        s.run(
            "MATCH (a:ThreatActor {merge_key:'apt-rel-test'}) "
            "MERGE (t:TTP {technique_id:'T1059'}) SET t.test_fixture = true "
            "MERGE (a)-[:USES]->(t)"
        ).consume()

    assert _score(driver).centrality == 0.1


def test_categorized_as_does_not_count_toward_centrality(driver):
    """Spec C3: CATEGORIZED_AS is structural, not an assertion. Counting it would give
    every enriched CVE free centrality for merely having a CWE."""
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-6001'}) "
            "SET c.test_fixture = true, c.first_seen = $now "
            "MERGE (w:CWE {cwe_id:'CWE-79'}) SET w.test_fixture = true "
            "MERGE (c)-[:CATEGORIZED_AS]->(w)",
            now=NOW,
        ).consume()
    assert _score(driver, label="CVE", key="CVE-2026-6001").centrality == 0.0


def test_credibility_is_the_max_over_mentioning_sources(driver):
    """max, not mean: one highly-credible source is enough, and low-credibility noise
    must not drag down a well-sourced item."""
    with driver.session() as s:
        s.run(
            "MERGE (a:ThreatActor {merge_key:'apt-rel-test'}) "
            "SET a.test_fixture = true, a.first_seen = $now "
            "MERGE (s1:Source {url:'https://low.example'}) "
            "SET s1.test_fixture = true, s1.credibility_score = 0.2 "
            "MERGE (s2:Source {url:'https://high.example'}) "
            "SET s2.test_fixture = true, s2.credibility_score = 0.9 "
            "MERGE (a1:Article {source_guid_key:'low::1'}) SET a1.test_fixture = true "
            "MERGE (a2:Article {source_guid_key:'high::1'}) SET a2.test_fixture = true "
            "MERGE (a1)-[:MENTIONS]->(a) MERGE (a2)-[:MENTIONS]->(a) "
            "MERGE (a1)-[:PUBLISHED_BY]->(s1) MERGE (a2)-[:PUBLISHED_BY]->(s2)",
            now=NOW,
        ).consume()
    assert _score(driver).credibility == 0.9


def test_novelty_keys_off_last_significant_event_over_first_seen(driver):
    """An old entity that just became active again re-spikes: old severe things becoming
    active ARE news."""
    with driver.session() as s:
        s.run(
            "MERGE (a:ThreatActor {merge_key:'apt-rel-test'}) SET a.test_fixture = true, "
            "a.first_seen = $old, a.last_significant_event = $now",
            old=NOW - timedelta(days=365), now=NOW,
        ).consume()
    assert _score(driver).novelty == 1.0


def test_novelty_falls_back_to_first_seen(driver):
    with driver.session() as s:
        s.run(
            "MERGE (a:ThreatActor {merge_key:'apt-rel-test'}) SET a.test_fixture = true, "
            "a.first_seen = $seen",
            seen=NOW - timedelta(days=7),
        ).consume()
    assert _score(driver).novelty == pytest.approx(0.5)


def test_time_of_day_is_not_truncated(driver):
    """Every other fixture here sits at exactly midnight, which hides a whole class of
    bug: `datetime` subclasses `date`, so if _age_days checked the `date` arm first every
    real timestamp would silently truncate to midnight. Production timestamps are never
    midnight -- the handler stamps `datetime.now(timezone.utc)`.
    """
    with driver.session() as s:
        s.run(
            "MERGE (a:ThreatActor {merge_key:'apt-rel-test'}) SET a.test_fixture = true, "
            "a.first_seen = $seen",
            seen=NOW - timedelta(days=7) + timedelta(hours=18, minutes=30),
        ).consume()
    # age is 6.229166... days, NOT 7.0: 0.5 ** (6.229166/7).
    # Truncating the time of day to midnight would give age 7.0 -> novelty exactly 0.5.
    assert _score(driver).novelty == pytest.approx(0.5396586, abs=1e-6)


def test_score_is_stored_on_the_node(driver):
    with driver.session() as s:
        s.run(
            "MERGE (a:ThreatActor {merge_key:'apt-rel-test'}) SET a.test_fixture = true, "
            "a.first_seen = $now", now=NOW,
        ).consume()
    _score(driver)
    with driver.session() as s:
        node = s.run(
            "MATCH (a:ThreatActor {merge_key:'apt-rel-test'}) RETURN a AS a"
        ).single()["a"]
    assert node["relevance_score"] == pytest.approx(0.5)


def test_all_three_components_combine_on_one_realistic_entity(driver):
    """Every other test isolates one dimension. Production entities have all three at
    once, and the article fan-out has to collapse before the assertion degree is counted
    -- otherwise credibility is computed per-article and the read returns several rows.
    """
    with driver.session() as s:
        s.run(
            "MERGE (a:ThreatActor {merge_key:'apt-rel-test'}) "
            "SET a.test_fixture = true, a.first_seen = $seen "
            "MERGE (s1:Source {url:'https://mid.example'}) "
            "SET s1.test_fixture = true, s1.credibility_score = 0.3 "
            "MERGE (s2:Source {url:'https://top.example'}) "
            "SET s2.test_fixture = true, s2.credibility_score = 0.85 "
            "MERGE (a1:Article {source_guid_key:'mid::1'}) SET a1.test_fixture = true "
            "MERGE (a2:Article {source_guid_key:'top::1'}) SET a2.test_fixture = true "
            "MERGE (a3:Article {source_guid_key:'mid::2'}) SET a3.test_fixture = true "
            "MERGE (a1)-[:MENTIONS]->(a) MERGE (a2)-[:MENTIONS]->(a) "
            "MERGE (a3)-[:MENTIONS]->(a) "
            "MERGE (a1)-[:PUBLISHED_BY]->(s1) MERGE (a3)-[:PUBLISHED_BY]->(s1) "
            "MERGE (a2)-[:PUBLISHED_BY]->(s2) "
            "MERGE (t:TTP {technique_id:'T1566'}) SET t.test_fixture = true "
            "MERGE (m:MalwareFamily {merge_key:'mal-rel-1'}) SET m.test_fixture = true "
            "MERGE (a)-[:USES]->(t) MERGE (a)-[:USES]->(m)",
            seen=NOW - timedelta(days=7),
        ).consume()

    result = _score(driver)

    assert result.novelty == pytest.approx(0.5)      # one half-life
    assert result.credibility == pytest.approx(0.85)  # max, over 3 articles / 2 sources
    assert result.centrality == pytest.approx(0.2)    # 2 assertion edges / c=10
    # 0.5*0.5 + 0.25*0.85 + 0.25*0.2
    assert result.score == pytest.approx(0.5125)


def test_an_ioc_with_a_raw_string_first_seen_scores_instead_of_raising(driver):
    """A `first_seen` value can reach `_age_days` as a plain STRING from any source --
    e.g. a legacy IOC node written before an L1 writer's temporal properties were
    normalized -- and IOC is a scored label. Scoring must never be the thing that raises
    on data the graph already contains: the daily novelty sweep scans every IOC in one
    transaction, so one raise rolls the batch back, the cursor never advances, and the
    sweep never terminates.
    """
    with driver.session() as s:
        s.run(
            "MERGE (i:IOC {value_type_key:'sha256|abc123'}) "
            "SET i.test_fixture = true, i.first_seen = '2026-07-20 09:00:00'"
        ).consume()

    result = _score(driver, label="IOC", key="sha256|abc123")

    # Uninterpretable clock means OLDEST, not newest.
    assert result is not None
    assert result.novelty == 0.0


def test_a_date_typed_clock_is_accepted(driver):
    """Neo4j `date` round-trips to a `datetime.date`, which has no tzinfo. It is a real
    timestamp and must produce a real age, not be discarded as uninterpretable."""
    with driver.session() as s:
        s.run(
            "MERGE (a:ThreatActor {merge_key:'apt-rel-test'}) SET a.test_fixture = true, "
            "a.first_seen = date('2026-07-23')"
        ).consume()
    assert _score(driver).novelty == pytest.approx(0.5)  # 7 days -> one half-life


def test_an_entity_with_no_clock_at_all_is_treated_as_oldest_not_newest(driver):
    """Nothing in src/ writes `first_seen` on CVE/ThreatActor/MalwareFamily/Campaign, so
    on first deploy this is the whole graph. Defaulting to novelty 1.0 would make every
    untimestamped node outrank a genuinely new one that carries a real timestamp.
    """
    with driver.session() as s:
        s.run(
            "MERGE (a:ThreatActor {merge_key:'apt-rel-test'}) SET a.test_fixture = true"
        ).consume()
    assert _score(driver).novelty == 0.0


def test_missing_entity_returns_none(driver):
    assert _score(driver, key="does-not-exist") is None


def test_rejects_an_uninterpolatable_label(driver):
    with pytest.raises(ValueError, match="invalid label"):
        _score(driver, label="ThreatActor) DETACH DELETE (n")


def test_rejects_a_syntactically_valid_but_unscored_label(driver):
    """TTP is a real label with a real key property, just not one that carries a
    relevance_score. It must be rejected by name, not merely by failing validation."""
    with pytest.raises(ValueError, match="relevance_score"):
        _score(driver, label="TTP", key="T1059")


def test_a_key_map_entry_alone_does_not_make_a_label_scorable(driver, monkeypatch):
    """KEY_PROP_BY_LABEL is a general-purpose map; SCORED_LABELS is the authority on what
    carries a relevance_score. Without an explicit SCORED_LABELS check, adding one row to
    that map -- Article and Source are the obvious future rows -- would silently start
    writing relevance_score onto Articles.
    """
    monkeypatch.setitem(_shared.KEY_PROP_BY_LABEL, "Article", "source_guid_key")
    with pytest.raises(ValueError, match="relevance_score"):
        _score(driver, label="Article", key="src::1")
