import json

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.delivery.dashboard_handler import (
    stats_handler,
    subgraph_handler,
    top_cves_handler,
)


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


def test_top_cves_handler_returns_200_with_json_list(driver):
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-H1', severity_score: 0.5, description: '', "
            "  cvss_score: 5.0, epss_score: 0.1, exploited_in_wild: false, "
            "  relevance_score: 0.1, severity_band: 'medium', "
            "  published_date: '2026-01-01', test_fixture: true})"
        )
    response = top_cves_handler({"queryStringParameters": {"limit": "5"}}, None)
    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert any(c["cve_id"] == "CVE-H1" for c in body["cves"])


def test_top_cves_handler_uses_default_limit_when_missing(driver):
    response = top_cves_handler({"queryStringParameters": None}, None)
    assert response["statusCode"] == 200


def test_stats_handler_returns_200(driver):
    response = stats_handler({}, None)
    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert "total_cves" in body
    assert "severity_distribution" in body


def test_subgraph_handler_returns_404_for_unknown_id(driver):
    response = subgraph_handler({"pathParameters": {"id": "4:00000000-0000-0000-0000-000000000000:9999"}}, None)
    assert response["statusCode"] == 404
