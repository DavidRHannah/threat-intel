import threading
from datetime import datetime, timezone

import pytest

from src.common.config import get_config
from src.common.graph.assertion_edges import (
    upsert_authoritative_assertion,
    upsert_inferred_assertion,
)
from src.common.neo4j_driver import close_driver, get_driver


@pytest.fixture
def driver():
    # Use the get_driver() singleton, not a hand-rolled GraphDatabase.driver: it is what
    # L1/L2 call in production, and it keeps connection config in src/common/config.py
    # rather than duplicated across every L3 test file (§2).
    d = get_driver()
    d.verify_connectivity()
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-0002'}) SET c.test_fixture = true "
            "MERGE (a:ThreatActor {merge_key:'apt-assert-test'}) SET a.test_fixture = true"
        ).consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


def _edge(driver):
    with driver.session() as s:
        return s.run(
            "MATCH (:CVE {cve_id:'CVE-2026-0002'})-[r:EXPLOITED_BY]->"
            "(:ThreatActor {merge_key:'apt-assert-test'}) RETURN r AS r"
        ).single()["r"]


def test_authoritative_then_inferred_unions_origin(driver):
    now = datetime.now(timezone.utc)
    with driver.session() as s:
        s.execute_write(lambda tx: upsert_authoritative_assertion(
            tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0002"},
            end_label="ThreatActor", end_key={"merge_key": "apt-assert-test"},
            rel_type="EXPLOITED_BY", feed_source="otx", credibility_score=0.6, now=now,
        ))
        s.execute_write(lambda tx: upsert_inferred_assertion(
            tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0002"},
            end_label="ThreatActor", end_key={"merge_key": "apt-assert-test"},
            rel_type="EXPLOITED_BY", story_cluster_id="sc-1", contribution=0.8,
            source_article_ids=["art-1"], now=now,
        ))
    r = _edge(driver)
    assert set(r["origin"]) == {"authoritative", "inferred"}  # FR-RG-04


def test_confidence_is_max_of_credibility_and_inferred(driver):
    now = datetime.now(timezone.utc)
    with driver.session() as s:
        s.execute_write(lambda tx: upsert_authoritative_assertion(
            tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0002"},
            end_label="ThreatActor", end_key={"merge_key": "apt-assert-test"},
            rel_type="EXPLOITED_BY", feed_source="otx", credibility_score=0.6, now=now,
        ))
        s.execute_write(lambda tx: upsert_inferred_assertion(
            tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0002"},
            end_label="ThreatActor", end_key={"merge_key": "apt-assert-test"},
            rel_type="EXPLOITED_BY", story_cluster_id="sc-1", contribution=0.8,
            source_article_ids=["art-1"], now=now,
        ))
    assert _edge(driver)["confidence"] == 0.8  # FR-RG-05


def test_two_distinct_clusters_combine_by_noisy_or(driver):
    # Pins the noisy-OR formula itself, which is the reason this module exists. Without
    # this, `prior + contribution` passes every other test in the file: they only ever
    # exercise a FIRST inferred write (prior = 0.0), where both formulas agree.
    # 1 - (1 - 0.5) * (1 - 0.5) = 0.75, whereas a naive sum gives 1.0.
    now = datetime.now(timezone.utc)
    with driver.session() as s:
        for cluster in ("sc-a", "sc-b"):
            s.execute_write(lambda tx, c=cluster: upsert_inferred_assertion(
                tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0002"},
                end_label="ThreatActor", end_key={"merge_key": "apt-assert-test"},
                rel_type="EXPLOITED_BY", story_cluster_id=c, contribution=0.5,
                source_article_ids=[f"art-{c}"], now=now,
            ))
    r = _edge(driver)
    assert r["inferred_confidence"] == 0.75  # FR-RG-05: noisy-OR, not a sum
    assert r["confidence"] == 0.75  # FR-RG-05: max() tracks the combined value
    assert sorted(r["contributing_story_cluster_ids"]) == ["sc-a", "sc-b"]
    assert r["supporting_article_count"] == 2


def test_confidence_is_derived_from_components_not_ratcheted(driver):
    # A ratchet (max against the previously stored confidence) passes every other test in
    # this file. It is caught only by making a component FALL: here inferred_confidence is
    # lowered out-of-band, exactly as L4's temporal decay will do. A ratchet leaves
    # confidence at 0.9; deriving from the components gives max(0.6, 0.2) = 0.6.
    now = datetime.now(timezone.utc)
    with driver.session() as s:
        s.execute_write(lambda tx: upsert_inferred_assertion(
            tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0002"},
            end_label="ThreatActor", end_key={"merge_key": "apt-assert-test"},
            rel_type="EXPLOITED_BY", story_cluster_id="sc-decay", contribution=0.9,
            source_article_ids=["art-decay"], now=now,
        ))
        # Simulate L4 decay lowering the inferred component.
        s.run(
            "MATCH (:CVE {cve_id:'CVE-2026-0002'})-[r:EXPLOITED_BY]->"
            "(:ThreatActor {merge_key:'apt-assert-test'}) SET r.inferred_confidence = 0.2"
        ).consume()
        s.execute_write(lambda tx: upsert_authoritative_assertion(
            tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0002"},
            end_label="ThreatActor", end_key={"merge_key": "apt-assert-test"},
            rel_type="EXPLOITED_BY", feed_source="otx", credibility_score=0.6, now=now,
        ))
    r = _edge(driver)
    assert r["authoritative_confidence"] == 0.6
    assert r["inferred_confidence"] == 0.2  # not clobbered by the authoritative write
    assert r["confidence"] == 0.6  # FR-RG-05: max over origins, not a ratchet at 0.9


def test_reprocessing_same_story_cluster_is_a_confidence_noop(driver):
    now = datetime.now(timezone.utc)
    with driver.session() as s:
        for _ in range(2):
            s.execute_write(lambda tx: upsert_inferred_assertion(
                tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0002"},
                end_label="ThreatActor", end_key={"merge_key": "apt-assert-test"},
                rel_type="EXPLOITED_BY", story_cluster_id="sc-dup", contribution=0.5,
                source_article_ids=["art-dup"], now=now,
            ))
    r = _edge(driver)
    assert r["inferred_confidence"] == 0.5  # FR-RG-05: re-emitted cluster is a no-op
    assert r["supporting_article_count"] == 1


def test_source_article_ids_bounded_while_count_keeps_accumulating(driver, monkeypatch):
    # Each of the 5 writes is a distinct cluster contributing a distinct article, so the
    # count is exact here. Note supporting_article_count is a monotonic count of article
    # CONTRIBUTIONS, not of distinct articles: past the cap, ids are deduped against the
    # capped list, so an article outside the stored window would be counted again. That is
    # inherent to the capped design — FR-RG-06 was amended to say so.
    monkeypatch.setenv("CROSSROADS_SOURCE_ARTICLE_IDS_CAP", "2")
    get_config.cache_clear()
    now = datetime.now(timezone.utc)
    with driver.session() as s:
        for i in range(5):
            s.execute_write(lambda tx, i=i: upsert_inferred_assertion(
                tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0002"},
                end_label="ThreatActor", end_key={"merge_key": "apt-assert-test"},
                rel_type="EXPLOITED_BY", story_cluster_id=f"sc-{i}", contribution=0.3,
                source_article_ids=[f"art-{i}"], now=now,
            ))
    r = _edge(driver)
    assert len(r["source_article_ids"]) <= 2       # FR-RG-06
    assert r["supporting_article_count"] == 5       # FR-RG-06
    get_config.cache_clear()


def test_concurrent_inferred_writes_lose_no_contribution(driver):
    # Regression test for the read-modify-write race in `_existing`: N threads each write a
    # DISTINCT story_cluster_id/article_id concurrently onto the SAME edge. Same-transaction
    # is not same-lock — Neo4j takes no read locks by default — so an unlocked `_existing`
    # read lets two concurrent writers derive their writes from identical stale pre-state,
    # silently losing one noisy-OR contribution and one supporting_article_count increment.
    # With `_existing` acquiring the endpoint lock itself (re-entrant with merge_relationship's
    # later lock), the whole read-modify-write serializes and no contribution is lost.
    n = 10
    errors = []

    def _write(i):
        try:
            with driver.session() as s:
                s.execute_write(lambda tx: upsert_inferred_assertion(
                    tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0002"},
                    end_label="ThreatActor", end_key={"merge_key": "apt-assert-test"},
                    rel_type="EXPLOITED_BY", story_cluster_id=f"sc-conc-{i}", contribution=0.5,
                    source_article_ids=[f"art-conc-{i}"], now=datetime.now(timezone.utc),
                ))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=_write, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not errors  # no deadlock
    r = _edge(driver)
    assert r["supporting_article_count"] == n
    assert sorted(r["contributing_story_cluster_ids"]) == sorted(f"sc-conc-{i}" for i in range(n))


# --- Task 5.0: the three-state outcome (shared L3 contract) -------------------------


def test_upsert_inferred_assertion_returns_three_distinct_states(driver):
    """`merge_relationship`'s coarse created/matched cannot express the distinction L4
    needs: on an EXISTING edge it says `matched` both when a NEW story cluster raises the
    noisy-OR (genuine new evidence) and when the SAME cluster is re-emitted (a true
    no-op). Collapsing those suppresses the novelty spike for real news -- so the
    discriminator is `already_seen`, not whether a row was written.
    """
    now = datetime.now(timezone.utc)
    key = {"merge_key": "apt-assert-test"}

    def _upsert(cluster_id):
        with driver.session() as s:
            return s.execute_write(lambda tx: upsert_inferred_assertion(
                tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0002"},
                end_label="ThreatActor", end_key=key,
                rel_type="EXPLOITED_BY", story_cluster_id=cluster_id, contribution=0.5,
                source_article_ids=["art-1"], now=now,
            ))

    assert _upsert("sc-a") == "created"    # the edge is new
    assert _upsert("sc-b") == "updated"    # a NEW cluster contributed
    assert _upsert("sc-b") == "matched"    # the SAME cluster re-emitted: no-op


def test_a_re_emitted_cluster_does_not_move_confidence(driver):
    """The `updated`/`matched` split must track the actual noisy-OR, not just bookkeeping."""
    now = datetime.now(timezone.utc)
    key = {"merge_key": "apt-assert-test"}

    def _upsert(cluster_id):
        with driver.session() as s:
            return s.execute_write(lambda tx: upsert_inferred_assertion(
                tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0002"},
                end_label="ThreatActor", end_key=key,
                rel_type="EXPLOITED_BY", story_cluster_id=cluster_id, contribution=0.5,
                source_article_ids=["art-1"], now=now,
            ))

    def _confidence():
        with driver.session() as s:
            return s.run(
                "MATCH (:CVE {cve_id:'CVE-2026-0002'})-[r:EXPLOITED_BY]->"
                "(:ThreatActor {merge_key:'apt-assert-test'}) "
                "RETURN r.inferred_confidence AS c"
            ).single()["c"]

    _upsert("sc-a")
    after_first = _confidence()
    assert _upsert("sc-b") == "updated"
    after_new_cluster = _confidence()
    assert after_new_cluster > after_first          # genuine new evidence moved it
    assert _upsert("sc-b") == "matched"
    assert _confidence() == after_new_cluster       # the no-op moved nothing
