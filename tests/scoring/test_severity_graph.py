import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.scoring.knobs import SeverityKnobs
from src.scoring.severity import score_cve

K = SeverityKnobs.from_config()


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


def _seed(driver, **props):
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-5001'}) SET c.test_fixture = true, c += $props",
            props=props,
        ).consume()


def _read(driver):
    with driver.session() as s:
        return s.run(
            "MATCH (c:CVE {cve_id:'CVE-2026-5001'}) RETURN c AS c"
        ).single()["c"]


def test_fr_es_02_scores_are_stored_properties_not_computed_at_read_time(driver):
    """FR-ES-02: Given a scored CVE, When queried, Then severity_score/severity_band are
    stored properties."""
    _seed(driver, cvss_score=9.8, epss_score=0.91, exploited_in_wild=True)
    with driver.session() as s:
        s.run(
            "MATCH (c:CVE {cve_id:'CVE-2026-5001'}) "
            "MERGE (a:ThreatActor {merge_key:'apt-sev-02'}) "
            "SET a.test_fixture = true MERGE (c)-[:EXPLOITED_BY]->(a)"
        ).consume()
        s.execute_write(lambda tx: score_cve(tx, cve_id="CVE-2026-5001", knobs=K))

    node = _read(driver)
    assert node["severity_band"] == "critical"
    assert node["severity_score"] >= 0.8
    assert node["severity_impact"] == pytest.approx(0.98)
    assert node["severity_likelihood"] == 1.0


def test_fr_es_05_bare_stub_gets_unknown_band(driver):
    _seed(driver)
    with driver.session() as s:
        s.execute_write(lambda tx: score_cve(tx, cve_id="CVE-2026-5001", knobs=K))
    node = _read(driver)
    assert node["severity_band"] == "unknown"
    assert node.get("severity_score") is None


def test_fr_es_03_new_exploited_by_edge_changes_the_score(driver):
    """FR-ES-03: Given a new EXPLOITED_BY edge on a CVE, When the event fires, Then that
    CVE's severity_score is recomputed."""
    _seed(driver, cvss_score=5.0, epss_score=0.1)
    with driver.session() as s:
        s.execute_write(lambda tx: score_cve(tx, cve_id="CVE-2026-5001", knobs=K))
        before = _read(driver)["severity_score"]

        s.run(
            "MATCH (c:CVE {cve_id:'CVE-2026-5001'}) "
            "MERGE (a:ThreatActor {merge_key:'apt-sev-test'}) "
            "SET a.test_fixture = true MERGE (c)-[:EXPLOITED_BY]->(a)"
        ).consume()
        s.execute_write(lambda tx: score_cve(tx, cve_id="CVE-2026-5001", knobs=K))

    assert _read(driver)["severity_score"] > before


def test_adoption_counts_distinct_exploiters_only(driver):
    _seed(driver, cvss_score=5.0, epss_score=0.1)
    with driver.session() as s:
        s.run(
            "MATCH (c:CVE {cve_id:'CVE-2026-5001'}) "
            "MERGE (a:ThreatActor {merge_key:'apt-sev-1'}) SET a.test_fixture = true "
            "MERGE (m:MalwareFamily {merge_key:'mal-sev-1'}) SET m.test_fixture = true "
            "MERGE (c)-[:EXPLOITED_BY]->(a) MERGE (c)-[:EXPLOITED_BY]->(m)"
        ).consume()
        result = s.execute_write(
            lambda tx: score_cve(tx, cve_id="CVE-2026-5001", knobs=K)
        )
    assert result.adoption == pytest.approx(2 / K.adoption_saturation_k)


def test_missing_cve_returns_none_rather_than_raising(driver):
    with driver.session() as s:
        assert s.execute_write(
            lambda tx: score_cve(tx, cve_id="CVE-DOES-NOT-EXIST", knobs=K)
        ) is None


def test_regressing_to_unscorable_clears_the_stale_score(driver):
    """A CVE that loses its inputs (e.g. a withdrawn CVSS) must not keep the score from a
    previous run -- the write sets every property unconditionally, including the nulls."""
    _seed(driver, cvss_score=9.8, epss_score=0.91, exploited_in_wild=True)
    with driver.session() as s:
        s.execute_write(lambda tx: score_cve(tx, cve_id="CVE-2026-5001", knobs=K))
    scored = _read(driver)
    assert scored["severity_score"] is not None
    assert scored["severity_band"] == "high"

    with driver.session() as s:
        s.run(
            "MATCH (c:CVE {cve_id:'CVE-2026-5001'}) "
            "REMOVE c.cvss_score, c.epss_score SET c.exploited_in_wild = false"
        ).consume()
        s.execute_write(lambda tx: score_cve(tx, cve_id="CVE-2026-5001", knobs=K))

    regressed = _read(driver)
    assert regressed.get("severity_score") is None
    assert regressed.get("severity_impact") is None
    assert regressed.get("severity_likelihood") is None
    assert regressed["severity_band"] == "unknown"


def test_rescoring_is_idempotent(driver):
    _seed(driver, cvss_score=7.5, epss_score=0.4)
    with driver.session() as s:
        s.execute_write(lambda tx: score_cve(tx, cve_id="CVE-2026-5001", knobs=K))
        first = dict(_read(driver))
        s.execute_write(lambda tx: score_cve(tx, cve_id="CVE-2026-5001", knobs=K))
    assert dict(_read(driver)) == first
