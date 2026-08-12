import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.interop.taxii_handler import collections_handler, discovery_handler, objects_handler


@pytest.fixture
def driver():
    """Local fixture, same convention as every other Neo4j-backed test file in this
    repo -- there is no shared conftest.py. Every node/edge this file creates must be
    tagged `test_fixture: true` so this cleanup finds it -- `objects_handler` queries
    the WHOLE exportable graph with no per-test key scoping, so leftover untagged data
    from a earlier failed test would silently change these tests' expected sets."""
    d = get_driver()
    d.verify_connectivity()
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


@pytest.fixture(autouse=True)
def _mock_dynamodb_by_default():
    """`objects_handler` now also reads a DynamoDB reconciliation-tombstone table
    (`scan_revoked_tombstones`) on every call. `src.common.config.get_config` is
    `lru_cache`d, so a value monkeypatched by an earlier-running test file (e.g.
    `test_merge_tombstone.py`, which sets the same `revoked_stix_ids_table_name` key)
    can leak into this file's tests via the cache even though their own environment
    never set it -- letting a real, unconfigured `boto3.resource("dynamodb")` call
    through. Default every test in this file to a mocked, empty scan; the one test
    that actually exercises the tombstone path
    (`test_objects_includes_reconciliation_tombstones`) supplies its own
    `@patch("boto3.resource")`, which takes precedence for the duration of that test."""
    with patch("boto3.resource") as mock_resource:
        mock_resource.return_value.Table.return_value.scan.return_value = {"Items": []}
        yield


def test_discovery_lists_the_one_collection():
    response = discovery_handler({}, None)
    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["title"]
    assert body["api_roots"]


def test_collections_returns_the_configured_collection():
    response = collections_handler({}, None)
    body = json.loads(response["body"])
    assert len(body["collections"]) == 1
    assert body["collections"][0]["id"] == "883d0e40-1e0e-4e2b-9a7c-8e2f6c5a1d90"


def test_objects_returns_only_gated_in_nodes(driver):
    ts = datetime(2026, 8, 1, tzinfo=timezone.utc)
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-2026-1', confidence: 0.9, last_updated: $ts, "
            "test_fixture: true}) "
            "CREATE (:CVE:Provisional {cve_id: 'CVE-2026-2', confidence: 0.9, "
            "last_updated: $ts, test_fixture: true})",
            ts=ts,
        )

    event = {"queryStringParameters": None}
    response = objects_handler(event, None)
    body = json.loads(response["body"])
    ids = {obj["name"] for obj in body["objects"] if obj["type"] == "vulnerability"}
    assert ids == {"CVE-2026-1"}


def test_objects_marks_served_nodes_exported(driver):
    ts = datetime(2026, 8, 1, tzinfo=timezone.utc)
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-2026-1', confidence: 0.9, last_updated: $ts, "
            "test_fixture: true})",
            ts=ts,
        )

    objects_handler({"queryStringParameters": None}, None)

    with driver.session() as session:
        record = session.run(
            "MATCH (c:CVE {cve_id: 'CVE-2026-1'}) RETURN c.exported AS e"
        ).single()
    assert record["e"] is True


def test_objects_respects_added_after(driver):
    old = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-OLD', confidence: 0.9, last_updated: $old, "
            "test_fixture: true})",
            old=old,
        )

    event = {"queryStringParameters": {"added_after": "2026-06-01T00:00:00+00:00"}}
    response = objects_handler(event, None)
    body = json.loads(response["body"])
    assert body["objects"] == []


def test_objects_includes_sweep_revoked_object(driver):
    ts = datetime(2026, 8, 1, tzinfo=timezone.utc)
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-2026-1', confidence: 0.01, revoked: true, "
            "exported: false, last_updated: $ts, test_fixture: true})",
            ts=ts,
        )

    response = objects_handler({"queryStringParameters": None}, None)
    body = json.loads(response["body"])
    revoked = [o for o in body["objects"] if o.get("revoked") is True]
    assert len(revoked) == 1
    assert revoked[0]["name"] == "CVE-2026-1"


def test_objects_report_keeps_refs_to_previously_exported_objects(driver):
    """I1: object_refs must reflect ALL-TIME exported state, not just what this poll's
    response happens to include. CVE-2026-1 was exported on an earlier poll (exported:
    true, old last_updated) and so is excluded from THIS poll's own node page by
    `added_after` -- but the Article mentioning it is new. A Report with an empty
    object_refs is illegal STIX, so if the CVE's ref is dropped the whole Report silently
    vanishes from the poll, even though the consumer already has the CVE from before."""
    old = datetime(2026, 1, 1, tzinfo=timezone.utc)
    new = datetime(2026, 8, 1, tzinfo=timezone.utc)
    with driver.session() as session:
        session.run(
            "CREATE (c:CVE {cve_id: 'CVE-2026-1', confidence: 0.9, exported: true, "
            "last_updated: $old, test_fixture: true}) "
            "CREATE (a:Article {source_guid_key: 'art-1', title: 'T', fetched_at: $new, "
            "last_updated: $new, test_fixture: true}) "
            "CREATE (a)-[:MENTIONS]->(c)",
            old=old, new=new,
        )

    event = {"queryStringParameters": {"added_after": "2026-06-01T00:00:00+00:00"}}
    response = objects_handler(event, None)
    body = json.loads(response["body"])
    reports = [o for o in body["objects"] if o["type"] == "report"]
    assert len(reports) == 1
    assert any(ref.startswith("vulnerability--") for ref in reports[0]["object_refs"])


@patch("boto3.resource")
def test_objects_includes_reconciliation_tombstones(mock_boto_resource, monkeypatch):
    monkeypatch.setenv("CROSSROADS_REVOKED_STIX_IDS_TABLE_NAME", "revoked-stix-ids")
    mock_table = MagicMock()
    mock_table.scan.return_value = {
        "Items": [
            {
                "stix_id": "intrusion-set--00000000-0000-0000-0000-000000000000",
                "revoked_at": "2026-08-11T12:00:00+00:00",
            }
        ]
    }
    mock_boto_resource.return_value.Table.return_value = mock_table

    response = objects_handler({"queryStringParameters": None}, None)
    body = json.loads(response["body"])
    revoked_ids = {o["id"] for o in body["objects"] if o.get("revoked") is True}
    assert "intrusion-set--00000000-0000-0000-0000-000000000000" in revoked_ids
