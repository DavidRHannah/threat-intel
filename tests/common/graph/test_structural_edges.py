import pytest

from src.common.graph.structural_edges import resync_categorized_as
from src.common.neo4j_driver import close_driver, get_driver
from src.common.schema_bootstrap import bootstrap_schema

CVE_KEY = {"cve_id": "CVE-2026-0004"}


@pytest.fixture
def driver():
    # Use the get_driver() singleton, not a hand-rolled GraphDatabase.driver: it is what
    # L1/L2 call in production, and it keeps connection config in src/common/config.py
    # rather than duplicated across every L3 test file (§2).
    d = get_driver()
    d.verify_connectivity()
    bootstrap_schema(d)
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-0004'}) SET c.test_fixture = true "
            "MERGE (w1:CWE {cwe_id:'CWE-79'}) SET w1.test_fixture = true "
            "MERGE (w2:CWE {cwe_id:'CWE-89'}) SET w2.test_fixture = true"
        ).consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


def test_dropped_cwe_mapping_edge_is_deleted(driver):
    with driver.session() as s:
        s.execute_write(lambda tx: resync_categorized_as(
            tx, cve_key=CVE_KEY, cwe_keys=[{"cwe_id": "CWE-79"}, {"cwe_id": "CWE-89"}]
        ))
        s.execute_write(lambda tx: resync_categorized_as(
            tx, cve_key=CVE_KEY, cwe_keys=[{"cwe_id": "CWE-79"}]  # NVD dropped CWE-89
        ))
        remaining = list(s.run(
            "MATCH (:CVE {cve_id:'CVE-2026-0004'})-[:CATEGORIZED_AS]->(w:CWE) RETURN w.cwe_id AS id"
        ))
    assert {r["id"] for r in remaining} == {"CWE-79"}  # FR-RG-09


def test_new_mapping_reports_created_and_resync_reports_deleted(driver):
    # Regression pin (Task 6 brief note): merge_relationship's "created"/"matched" outcome
    # comes from the driver's relationships_created counter, not a property-based sentinel.
    # An earlier design would have made `created` silently always empty for this call shape
    # (on_create={}), so this test asserts `created` is actually populated on first sync.
    with driver.session() as s:
        first = s.execute_write(lambda tx: resync_categorized_as(
            tx, cve_key=CVE_KEY, cwe_keys=[{"cwe_id": "CWE-79"}, {"cwe_id": "CWE-89"}]
        ))
        second = s.execute_write(lambda tx: resync_categorized_as(
            tx, cve_key=CVE_KEY, cwe_keys=[{"cwe_id": "CWE-79"}]
        ))
    assert set(first["created"]) == {"CWE-79", "CWE-89"}  # FR-RG-09
    assert first["deleted"] == []
    assert second["created"] == []
    assert second["deleted"] == ["CWE-89"]  # FR-RG-09
