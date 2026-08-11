import threading

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.scoring.confidence import refine_from_mention, refine_provisional_confidence


@pytest.fixture
def driver():
    d = get_driver()
    d.verify_connectivity()
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
        s.run(
            "MERGE (a:ThreatActor:Provisional {merge_key:'apt-conf-test'}) "
            "SET a.test_fixture = true, a.confidence = 0.0 "
            "MERGE (c:ThreatActor {merge_key:'apt-canon-test'}) "
            "SET c.test_fixture = true, c.confidence = 1.0"
        ).consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


def _refine(driver, cluster, contribution, key="apt-conf-test"):
    with driver.session() as s:
        return s.execute_write(
            lambda tx: refine_provisional_confidence(
                tx,
                label="ThreatActor",
                key=key,
                story_cluster_id=cluster,
                contribution=contribution,
            )
        )


def test_fr_es_08_three_credible_stories_raise_confidence_toward_one(driver):
    """FR-ES-08: Given a provisional entity named across three credible distinct stories,
    When refined, Then its confidence rises toward 1."""
    _refine(driver, "cluster-a", 0.8)
    _refine(driver, "cluster-b", 0.8)
    final = _refine(driver, "cluster-c", 0.8)
    assert final > 0.99
    assert final < 1.0


def test_fr_es_08_canonical_nodes_are_never_refined(driver):
    """FR-ES-08: a canonical node stays at 1.0."""
    assert _refine(driver, "cluster-a", 0.1, key="apt-canon-test") is None
    with driver.session() as s:
        node = s.run(
            "MATCH (a:ThreatActor {merge_key:'apt-canon-test'}) RETURN a AS a"
        ).single()["a"]
    assert node["confidence"] == 1.0


def test_a_single_low_credibility_mention_stays_low(driver):
    assert _refine(driver, "cluster-a", 0.1) == pytest.approx(0.1)


def test_re_emitting_the_same_cluster_is_a_no_op(driver):
    """Idempotency under at-least-once delivery: the cluster-id list IS the check."""
    first = _refine(driver, "cluster-a", 0.8)
    assert _refine(driver, "cluster-a", 0.8) == first


def test_a_better_article_in_an_already_counted_cluster_raises_it(driver):
    """Design §5.3: `s_j` is the MAX over that cluster's mentioning articles.

    An incremental accumulator cannot express that -- it keeps whichever contribution
    arrived FIRST -- so a low-credibility blog delivered ahead of a top-tier vendor report
    on the SAME story would pin that cluster low permanently.
    """
    _refine(driver, "cluster-a", 0.1)
    assert _refine(driver, "cluster-a", 0.9) == pytest.approx(0.9)


def test_a_weaker_article_in_an_already_counted_cluster_does_not_lower_it(driver):
    """The other half of `max`: once a strong article has been counted, a weak one on the
    same story must not drag the cluster back down."""
    _refine(driver, "cluster-a", 0.9)
    assert _refine(driver, "cluster-a", 0.1) == pytest.approx(0.9)


def test_the_result_does_not_depend_on_arrival_order(driver):
    """SNS delivery order is nondeterministic. Confidence must be a function of WHICH
    (cluster, contribution) pairs were seen, never of the order they arrived in -- which
    an incremental form cannot guarantee once a cluster can be revised.
    """
    _refine(driver, "cluster-a", 0.2)
    _refine(driver, "cluster-a", 0.7)
    forwards = _refine(driver, "cluster-b", 0.5)

    with driver.session() as s:
        s.run(
            "MATCH (a:ThreatActor:Provisional {merge_key:'apt-conf-test'}) "
            "REMOVE a.contributing_story_cluster_ids, "
            "       a.contributing_story_cluster_scores "
            "SET a.confidence = 0.0"
        ).consume()

    _refine(driver, "cluster-b", 0.5)
    _refine(driver, "cluster-a", 0.7)
    backwards = _refine(driver, "cluster-a", 0.2)

    assert backwards == pytest.approx(forwards)


def test_corrupt_parallel_lists_are_refused_not_guessed(driver):
    """The ids and scores are written together and are meaningless apart. Padding a short
    list would invent per-cluster contributions that were never observed and bake them
    into every future recompute."""
    with driver.session() as s:
        s.run(
            "MATCH (a:ThreatActor:Provisional {merge_key:'apt-conf-test'}) "
            "SET a.contributing_story_cluster_ids = ['x', 'y'], "
            "    a.contributing_story_cluster_scores = [0.5]"
        ).consume()
    with pytest.raises(ValueError, match="corrupt"):
        _refine(driver, "cluster-a", 0.8)


def test_concurrent_contributions_are_not_lost(driver):
    """The lost-update test. Without apoc.lock.nodes, concurrent writers derive from the
    same stale pre-state and all but one contribution vanish."""
    errors = []

    def contribute(i):
        try:
            _refine(driver, f"cluster-{i}", 0.5)
        except Exception as exc:  # noqa: BLE001 - surfaced via the assert below
            errors.append(exc)

    threads = [threading.Thread(target=contribute, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors

    with driver.session() as s:
        node = s.run(
            "MATCH (a:ThreatActor {merge_key:'apt-conf-test'}) RETURN a AS a"
        ).single()["a"]
    assert len(node["contributing_story_cluster_ids"]) == 10
    assert node["confidence"] == pytest.approx(1 - 0.5**10)


def test_missing_node_returns_none(driver):
    assert _refine(driver, "cluster-a", 0.8, key="nope") is None


class _NoQueriesAllowed:
    """A transaction double that fails the test if any Cypher is issued at all.

    Asserting only on the return value cannot prove the unscored-label guard: with the
    guard deleted, `key_prop` is None and the query becomes `{None: $key}` -- `None` is a
    LEGAL Cypher property name, so it parses, matches nothing, and the function still
    returns None for the right-looking reason. The guard's actual job is that nothing
    unvalidated ever reaches .format(), so that is what gets asserted.
    """

    def run(self, *args, **kwargs):  # pragma: no cover - must never be reached
        raise AssertionError(f"no query may be built for an unscored label: {args!r}")


def test_an_unscored_label_never_reaches_cypher():
    """TTP has no key property in _shared, so resolve_key_prop returns None and the
    query must never be built."""
    assert (
        refine_provisional_confidence(
            _NoQueriesAllowed(),
            label="TTP",
            key="T1059",
            story_cluster_id="cluster-a",
            contribution=0.9,
        )
        is None
    )


def test_an_unscored_label_never_reaches_cypher_from_a_mention():
    assert (
        refine_from_mention(
            _NoQueriesAllowed(), label="TTP", key="T1059", article_key="src::1"
        )
        is None
    )


def _seed_mention(
    driver, *, credibility, extraction, cluster, provisional=True, with_source=True
):
    label = ":ThreatActor:Provisional" if provisional else ":ThreatActor"
    source = (
        "MERGE (s:Source {url:'https://example.test/feed'}) "
        "SET s.test_fixture = true, s.credibility_score = $credibility "
        if with_source
        else ""
    )
    published_by = "MERGE (a)-[:PUBLISHED_BY]->(s) " if with_source else ""
    extraction_conf = (
        "SET m.extraction_confidence = $extraction" if extraction is not None else ""
    )
    with driver.session() as s:
        s.run(
            source
            + "MERGE (a:Article {source_guid_key:'src::1'}) "
            "SET a.test_fixture = true, a.story_cluster_id = $cluster "
            + published_by
            + "MERGE (n" + label + " {merge_key:'apt-mention-test'}) "
            "SET n.test_fixture = true, n.confidence = $seed "
            "MERGE (a)-[m:MENTIONS]->(n) " + extraction_conf,
            credibility=credibility,
            extraction=extraction,
            cluster=cluster,
            seed=0.0 if provisional else 1.0,
        ).consume()


def _refine_mention(driver, *, label="ThreatActor", key="apt-mention-test"):
    with driver.session() as s:
        return s.execute_write(
            lambda tx: refine_from_mention(
                tx, label=label, key=key, article_key="src::1"
            )
        )


def test_fr_es_08_a_mention_contributes_credibility_times_extraction(driver):
    _seed_mention(driver, credibility=0.9, extraction=0.5, cluster="story-1")
    assert _refine_mention(driver) == pytest.approx(0.45)


def test_an_unclustered_article_contributes_under_its_own_id(driver):
    """A null story_cluster_id must not collapse every un-clustered article into one
    bucket where only the first one ever counts."""
    _seed_mention(driver, credibility=1.0, extraction=0.5, cluster=None)
    _refine_mention(driver)
    with driver.session() as s:
        node = s.run(
            "MATCH (n:ThreatActor {merge_key:'apt-mention-test'}) RETURN n AS n"
        ).single()["n"]
    assert node["contributing_story_cluster_ids"] == ["src::1"]


def test_an_article_with_no_source_contributes_zero_rather_than_crashing(driver):
    """`coalesce(s.credibility_score, 0.0)` is load-bearing, not defensive: an article
    with no PUBLISHED_BY is a real state both nlp/dedup/clustering.py and
    collection/rest/normalizer.py contemplate. Without the coalesce the OPTIONAL MATCH
    yields a null `s`, and the contribution multiply raises TypeError on a live path."""
    _seed_mention(driver, credibility=None, extraction=0.5, cluster="story-1",
                  with_source=False)
    assert _refine_mention(driver) == 0.0


def test_a_mention_with_no_extraction_confidence_contributes_zero(driver):
    """Defensive rather than reachable -- write_mentions_edge always sets the property --
    but the coalesce is what keeps that assumption from becoming a crash if it ever
    stops holding."""
    _seed_mention(driver, credibility=0.9, extraction=None, cluster="story-1")
    assert _refine_mention(driver) == 0.0


def test_a_mention_of_a_canonical_node_is_not_refined(driver):
    _seed_mention(driver, credibility=0.9, extraction=0.5, cluster="story-1",
                  provisional=False)
    assert _refine_mention(driver) is None


def test_a_mention_from_an_unrelated_article_is_not_applied(driver):
    _seed_mention(driver, credibility=0.9, extraction=0.5, cluster="story-1")
    with driver.session() as s:
        assert (
            s.execute_write(
                lambda tx: refine_from_mention(
                    tx, label="ThreatActor", key="apt-conf-test", article_key="src::1"
                )
            )
            is None
        )


