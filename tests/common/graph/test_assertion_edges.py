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
    assert r["inferred_confidence"] == 0.5
    assert r["supporting_article_count"] == 1


def test_source_article_ids_bounded_but_count_reflects_true_total(driver, monkeypatch):
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
