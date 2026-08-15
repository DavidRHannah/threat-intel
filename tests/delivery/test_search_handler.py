import json

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.delivery.search_handler import fetch_search_results, handler


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


def test_search_matches_cve_by_id_case_insensitive(driver):
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-2026-99999', description: 'RCE', "
            "  severity_score: 0.5, test_fixture: true})"
        )
    with driver.session() as session:
        rows = session.execute_read(
            lambda tx: fetch_search_results(tx, query="cve-2026-99999", limit=20)
        )
    assert rows[0]["_type"] == "cve"
    assert rows[0]["cve_id"] == "CVE-2026-99999"


def test_search_matches_actor_by_name_substring(driver):
    with driver.session() as session:
        session.run(
            "CREATE (:ThreatActor {merge_key: 'apt-search', name: 'APT Search Test', "
            "  relevance_score: 0.5, test_fixture: true})"
        )
    with driver.session() as session:
        rows = session.execute_read(
            lambda tx: fetch_search_results(tx, query="search test", limit=20)
        )
    assert any(r["_type"] == "actor" and r["name"] == "APT Search Test" for r in rows)


def test_search_no_match_returns_empty_list(driver):
    with driver.session() as session:
        rows = session.execute_read(
            lambda tx: fetch_search_results(tx, query="zzz-no-such-thing-zzz", limit=20)
        )
    assert rows == []


def test_handler_requires_query_param(driver):
    response = handler({"queryStringParameters": None}, None)
    assert response["statusCode"] == 400


def test_handler_returns_results_key(driver):
    response = handler({"queryStringParameters": {"q": "zzz-nomatch"}}, None)
    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["results"] == []
