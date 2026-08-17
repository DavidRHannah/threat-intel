# tests/delivery/test_assets_handler.py
import json

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.delivery.assets_handler import (
    all_assets_cves_handler,
    asset_cves_handler,
    create_asset_handler,
    delete_asset_handler,
    known_vendor_products_handler,
    list_assets_handler,
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


def test_create_asset_handler_returns_201_and_match_count(driver, monkeypatch):
    monkeypatch.setattr("src.delivery.assets_handler.get_driver", lambda: driver)
    event = {"body": json.dumps({"vendor": "acme", "product": "x", "version": "1.0.0"})}
    resp = create_asset_handler(event, None)
    assert resp["statusCode"] == 201
    body = json.loads(resp["body"])
    assert body["asset"]["vendor"] == "acme"
    assert "match_count" in body
    with driver.session() as s:
        s.run("MATCH (a:Asset {asset_key:'acme::x::1.0.0'}) DETACH DELETE a").consume()


def test_create_asset_handler_400_when_missing_fields(driver, monkeypatch):
    monkeypatch.setattr("src.delivery.assets_handler.get_driver", lambda: driver)
    event = {"body": json.dumps({"vendor": "acme"})}
    resp = create_asset_handler(event, None)
    assert resp["statusCode"] == 400


def test_list_assets_handler(driver, monkeypatch):
    monkeypatch.setattr("src.delivery.assets_handler.get_driver", lambda: driver)
    with driver.session() as s:
        s.run("MERGE (a:Asset {asset_key:'k9', vendor:'v', product:'p', version:'1'})").consume()
    resp = list_assets_handler({}, None)
    assert resp["statusCode"] == 200
    assert any(a["asset_key"] == "k9" for a in json.loads(resp["body"])["assets"])
    with driver.session() as s:
        s.run("MATCH (a:Asset {asset_key:'k9'}) DETACH DELETE a").consume()


def test_delete_asset_handler_404_when_missing(driver, monkeypatch):
    monkeypatch.setattr("src.delivery.assets_handler.get_driver", lambda: driver)
    resp = delete_asset_handler({"pathParameters": {"id": "does-not-exist"}}, None)
    assert resp["statusCode"] == 404


def test_delete_asset_handler_200_when_present(driver, monkeypatch):
    monkeypatch.setattr("src.delivery.assets_handler.get_driver", lambda: driver)
    with driver.session() as s:
        s.run("MERGE (a:Asset {asset_key:'k10', vendor:'v', product:'p', version:'1'})").consume()
    resp = delete_asset_handler({"pathParameters": {"id": "k10"}}, None)
    assert resp["statusCode"] == 200
    assert json.loads(resp["body"])["deleted"] == "k10"


def test_asset_cves_handler_returns_cves_for_asset(driver, monkeypatch):
    monkeypatch.setattr("src.delivery.assets_handler.get_driver", lambda: driver)
    with driver.session() as s:
        s.run(
            "MERGE (a:Asset {asset_key:'k11', vendor:'v', product:'p', version:'1'}) "
            "MERGE (c:CVE {cve_id:'CVE-K11', severity_score:0.5}) "
            "MERGE (c)-[:AFFECTS]->(a)"
        ).consume()
    resp = asset_cves_handler({"pathParameters": {"id": "k11"}}, None)
    assert resp["statusCode"] == 200
    cve_ids = [c["cve_id"] for c in json.loads(resp["body"])["cves"]]
    assert "CVE-K11" in cve_ids
    with driver.session() as s:
        s.run("MATCH (a:Asset {asset_key:'k11'}) DETACH DELETE a").consume()
        s.run("MATCH (c:CVE {cve_id:'CVE-K11'}) DETACH DELETE c").consume()


def test_all_assets_cves_handler_returns_cves(driver, monkeypatch):
    monkeypatch.setattr("src.delivery.assets_handler.get_driver", lambda: driver)
    with driver.session() as s:
        s.run(
            "MERGE (a:Asset {asset_key:'k12', vendor:'v', product:'p', version:'1'}) "
            "MERGE (c:CVE {cve_id:'CVE-K12', severity_score:0.5}) "
            "MERGE (c)-[:AFFECTS]->(a)"
        ).consume()
    resp = all_assets_cves_handler({}, None)
    assert resp["statusCode"] == 200
    cve_ids = [c["cve_id"] for c in json.loads(resp["body"])["cves"]]
    assert "CVE-K12" in cve_ids
    with driver.session() as s:
        s.run("MATCH (a:Asset {asset_key:'k12'}) DETACH DELETE a").consume()
        s.run("MATCH (c:CVE {cve_id:'CVE-K12'}) DETACH DELETE c").consume()


def test_known_vendor_products_handler(driver, monkeypatch):
    monkeypatch.setattr("src.delivery.assets_handler.get_driver", lambda: driver)
    with driver.session() as s:
        s.run(
            "MERGE (:CPEMatch {match_criteria_id:'mc-x', vendor:'acme', product:'widget'})"
        ).consume()
    resp = known_vendor_products_handler({}, None)
    assert resp["statusCode"] == 200
    pairs = json.loads(resp["body"])["vendor_products"]
    assert any(p["vendor"] == "acme" and p["product"] == "widget" for p in pairs)
    with driver.session() as s:
        s.run("MATCH (m:CPEMatch {match_criteria_id:'mc-x'}) DETACH DELETE m").consume()


def test_known_vendor_products_handler_passes_the_q_prefix_through(driver, monkeypatch):
    """Finding #6's wiring half: the handler must forward `?q=` to the query, or the
    server-side narrowing exists but nothing can reach it."""
    monkeypatch.setattr("src.delivery.assets_handler.get_driver", lambda: driver)
    try:
        with driver.session() as s:
            s.run(
                "MERGE (:CPEMatch {match_criteria_id:'mc-q1', vendor:'alpha', product:'one'}) "
                "MERGE (:CPEMatch {match_criteria_id:'mc-q2', vendor:'omega', product:'two'})"
            ).consume()
        resp = known_vendor_products_handler({"queryStringParameters": {"q": "ome"}}, None)
        assert resp["statusCode"] == 200
        pairs = json.loads(resp["body"])["vendor_products"]
        vendors = {p["vendor"] for p in pairs}
        assert "omega" in vendors
        assert "alpha" not in vendors  # the prefix actually narrowed server-side
    finally:
        with driver.session() as s:
            s.run(
                "MATCH (m:CPEMatch) WHERE m.match_criteria_id IN ['mc-q1','mc-q2'] "
                "DETACH DELETE m"
            ).consume()
