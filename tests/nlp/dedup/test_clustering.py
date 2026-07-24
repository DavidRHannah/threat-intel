"""Tests for Step 3.2 of `plans/02-nlp.md`: cluster assignment, identity, and
merge (FR-DED-03, FR-DED-04, FR-DED-05, FR-DED-06).

Integration -- cluster state (`story_cluster_id`, `is_cluster_representative`,
`dedup_cluster_size`) lives on `Article` nodes in Neo4j, mirroring the `driver`
fixture pattern in `tests/nlp/resolution/test_deterministic.py` /
`tests/nlp/dedup/test_similarity.py`.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.nlp.dedup.clustering import assign_cluster
from src.nlp.messages import ResolvedArticle, ResolvedEntity

BASE_TIME = datetime(2026, 7, 1, tzinfo=timezone.utc)


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


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _make_article(
    driver,
    *,
    key: str,
    published_at: str,
    content_hash: str = "",
    cleaned_text: str = "",
    cve_id: str | None = None,
    source_url: str | None = None,
    credibility: float | None = None,
) -> None:
    with driver.session() as s:
        s.run(
            "MERGE (a:Article {source_guid_key: $key}) "
            "SET a.test_fixture = true, a.published_at = $published_at, "
            "a.content_hash = $content_hash, a.cleaned_text = $cleaned_text, "
            "a.dedup_cluster_size = 1",
            key=key,
            published_at=published_at,
            content_hash=content_hash,
            cleaned_text=cleaned_text,
        ).consume()
        if cve_id:
            s.run(
                "MERGE (c:CVE {cve_id: $cve_id}) SET c.test_fixture = true "
                "WITH c MATCH (a:Article {source_guid_key: $key}) "
                "MERGE (a)-[:MENTIONS]->(c)",
                cve_id=cve_id,
                key=key,
            ).consume()
        if source_url:
            s.run(
                "MERGE (src:Source {url: $url}) "
                "SET src.test_fixture = true, src.credibility_score = $credibility "
                "WITH src MATCH (a:Article {source_guid_key: $key}) "
                "MERGE (a)-[:PUBLISHED_BY]->(src)",
                url=source_url,
                key=key,
                credibility=credibility,
            ).consume()


def _resolved_article(
    key: str, published_at: str, cve_id: str | None = None
) -> ResolvedArticle:
    entities = (
        [
            ResolvedEntity(
                canonical_node_key=cve_id,
                entity_type="cve",
                resolution_status="resolved",
                node_confidence=1.0,
            )
        ]
        if cve_id
        else []
    )
    return ResolvedArticle(
        article_id=key,
        title="title",
        published_at=published_at,
        source_id=key.split("::")[0],
        resolved_entities=entities,
    )


def _get_article_state(driver, key: str) -> dict:
    with driver.session() as s:
        record = s.run(
            "MATCH (a:Article {source_guid_key: $key}) "
            "RETURN a.story_cluster_id AS story_cluster_id, "
            "a.is_cluster_representative AS is_cluster_representative, "
            "a.dedup_cluster_size AS dedup_cluster_size",
            key=key,
        ).single()
    return dict(record)


# FR-DED-03: novel story (no shared entities -> no candidates) -> new singleton cluster.
def test_novel_story_below_threshold_creates_new_singleton_cluster(driver):
    key = "dedup-clu-source::novel-1"
    _make_article(driver, key=key, published_at=_iso(BASE_TIME))
    article = _resolved_article(key, _iso(BASE_TIME))

    cluster_id = assign_cluster(driver, article)

    state = _get_article_state(driver, key)
    assert cluster_id
    assert state["story_cluster_id"] == cluster_id
    assert state["is_cluster_representative"] is True
    assert state["dedup_cluster_size"] == 1


# FR-DED-04: 3-article cluster -> shared story_cluster_id, earliest-published is representative.
def test_three_article_cluster_shares_id_and_earliest_is_representative(driver):
    cve = "CVE-2099-10001"
    key_a = "dedup-clu-source::fr04-a"
    key_b = "dedup-clu-source::fr04-b"
    key_c = "dedup-clu-source::fr04-c"
    # Identical content_hash across all three -> score() short-circuits to 1.0.
    content_hash = "identical-hash-fr04"

    _make_article(
        driver,
        key=key_a,
        published_at=_iso(BASE_TIME),
        content_hash=content_hash,
        cve_id=cve,
    )
    article_a = _resolved_article(key_a, _iso(BASE_TIME), cve_id=cve)
    assign_cluster(driver, article_a)

    _make_article(
        driver,
        key=key_b,
        published_at=_iso(BASE_TIME + timedelta(hours=1)),
        content_hash=content_hash,
        cve_id=cve,
    )
    article_b = _resolved_article(key_b, _iso(BASE_TIME + timedelta(hours=1)), cve_id=cve)
    assign_cluster(driver, article_b)

    _make_article(
        driver,
        key=key_c,
        published_at=_iso(BASE_TIME + timedelta(hours=2)),
        content_hash=content_hash,
        cve_id=cve,
    )
    article_c = _resolved_article(key_c, _iso(BASE_TIME + timedelta(hours=2)), cve_id=cve)
    cluster_id = assign_cluster(driver, article_c)

    state_a = _get_article_state(driver, key_a)
    state_b = _get_article_state(driver, key_b)
    state_c = _get_article_state(driver, key_c)

    assert state_a["story_cluster_id"] == cluster_id
    assert state_b["story_cluster_id"] == cluster_id
    assert state_c["story_cluster_id"] == cluster_id

    assert state_a["is_cluster_representative"] is True
    assert state_b["is_cluster_representative"] is False
    assert state_c["is_cluster_representative"] is False


# FR-DED-05: cluster of 4 -> representative's dedup_cluster_size == 4.
def test_cluster_of_four_representative_dedup_cluster_size_is_4(driver):
    cve = "CVE-2099-10002"
    content_hash = "identical-hash-fr05"
    keys = [f"dedup-clu-source::fr05-{i}" for i in range(4)]

    cluster_id = None
    for i, key in enumerate(keys):
        published_at = _iso(BASE_TIME + timedelta(hours=i))
        _make_article(
            driver,
            key=key,
            published_at=published_at,
            content_hash=content_hash,
            cve_id=cve,
        )
        article = _resolved_article(key, published_at, cve_id=cve)
        cluster_id = assign_cluster(driver, article)

    state_rep = _get_article_state(driver, keys[0])
    assert state_rep["is_cluster_representative"] is True
    assert state_rep["dedup_cluster_size"] == 4
    for key in keys[1:]:
        state = _get_article_state(driver, key)
        assert state["story_cluster_id"] == cluster_id
        assert state["is_cluster_representative"] is False


# FR-DED-06: article bridging clusters A and B -> merged under A's (older) id.
def test_bridging_article_merges_clusters_under_older_id(driver):
    cve_a = "CVE-2099-10003"
    cve_b = "CVE-2099-10004"

    # Cluster A: two articles, earlier published_at, identical content_hash.
    key_a1 = "dedup-clu-source::fr06-a1"
    key_a2 = "dedup-clu-source::fr06-a2"
    hash_a = "identical-hash-fr06-a"
    _make_article(
        driver, key=key_a1, published_at=_iso(BASE_TIME), content_hash=hash_a, cve_id=cve_a
    )
    assign_cluster(driver, _resolved_article(key_a1, _iso(BASE_TIME), cve_id=cve_a))
    _make_article(
        driver,
        key=key_a2,
        published_at=_iso(BASE_TIME + timedelta(hours=1)),
        content_hash=hash_a,
        cve_id=cve_a,
    )
    cluster_a_id = assign_cluster(
        driver, _resolved_article(key_a2, _iso(BASE_TIME + timedelta(hours=1)), cve_id=cve_a)
    )

    # Cluster B: two articles, later published_at, identical content_hash (different from A),
    # and lexical text shared with the bridge article (see below -- the bridge doesn't share
    # cluster B's content_hash, so it needs entity + lexical + time to clear the threshold).
    key_b1 = "dedup-clu-source::fr06-b1"
    key_b2 = "dedup-clu-source::fr06-b2"
    hash_b = "identical-hash-fr06-b"
    shared_text = "identical lexical text shared across cluster b and the bridging article"
    later = BASE_TIME + timedelta(days=1)
    _make_article(
        driver,
        key=key_b1,
        published_at=_iso(later),
        content_hash=hash_b,
        cleaned_text=shared_text,
        cve_id=cve_b,
    )
    assign_cluster(driver, _resolved_article(key_b1, _iso(later), cve_id=cve_b))
    _make_article(
        driver,
        key=key_b2,
        published_at=_iso(later + timedelta(hours=1)),
        content_hash=hash_b,
        cleaned_text=shared_text,
        cve_id=cve_b,
    )
    cluster_b_id = assign_cluster(
        driver, _resolved_article(key_b2, _iso(later + timedelta(hours=1)), cve_id=cve_b)
    )

    assert cluster_a_id != cluster_b_id

    # Bridging article: content_hash equal to hash_a matches cluster A at a definite 1.0 via
    # the short-circuit. It matches cluster B without a content_hash match -- via entity overlap
    # (mentions cve_b, 0.5 Jaccard against B's cve_b-only members), identical lexical text (1.0),
    # and time proximity, which together clear the 0.6 default threshold
    # (0.5*0.5 + 0.3*1.0 + 0.2*~0.98 ~= 0.75).
    key_bridge = "dedup-clu-source::fr06-bridge"
    bridge_time = later + timedelta(hours=2)
    _make_article(
        driver,
        key=key_bridge,
        published_at=_iso(bridge_time),
        content_hash=hash_a,
        cleaned_text=shared_text,
        cve_id=cve_a,
    )
    with driver.session() as s:
        s.run(
            "MATCH (a:Article {source_guid_key: $key}), (c:CVE {cve_id: $cve_id}) "
            "MERGE (a)-[:MENTIONS]->(c)",
            key=key_bridge,
            cve_id=cve_b,
        ).consume()

    bridge_article = ResolvedArticle(
        article_id=key_bridge,
        title="title",
        published_at=_iso(bridge_time),
        source_id="dedup-clu-source",
        resolved_entities=[
            ResolvedEntity(
                canonical_node_key=cve_a,
                entity_type="cve",
                resolution_status="resolved",
                node_confidence=1.0,
            ),
            ResolvedEntity(
                canonical_node_key=cve_b,
                entity_type="cve",
                resolution_status="resolved",
                node_confidence=1.0,
            ),
        ],
    )

    final_id = assign_cluster(driver, bridge_article)

    assert final_id == cluster_a_id

    for key in (key_a1, key_a2, key_b1, key_b2, key_bridge):
        state = _get_article_state(driver, key)
        assert state["story_cluster_id"] == cluster_a_id

    # Exactly one representative across the merged 5-member cluster.
    reps = [
        _get_article_state(driver, key)["is_cluster_representative"]
        for key in (key_a1, key_a2, key_b1, key_b2, key_bridge)
    ]
    assert reps.count(True) == 1
    assert _get_article_state(driver, key_a1)["is_cluster_representative"] is True

    rep_state = _get_article_state(driver, key_a1)
    assert rep_state["dedup_cluster_size"] == 5
