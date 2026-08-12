import json
from datetime import datetime, timezone

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.interop.watermark_handler import handler


@pytest.fixture
def driver():
    """Local fixture, same convention as every other Neo4j-backed test file in this
    repo (e.g. tests/nlp/resolution/test_reconciliation.py, tests/scoring/test_sweep.py)
    -- there is no shared conftest.py. Every node/edge this file creates must be tagged
    `test_fixture: true` so this cleanup finds it."""
    d = get_driver()
    d.verify_connectivity()
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


def _sns_record(message: dict) -> dict:
    return {"Sns": {"Message": json.dumps(message)}}


def test_node_write_stamps_last_updated(driver):
    with driver.session() as session:
        session.run("CREATE (:CVE {cve_id: 'CVE-2026-1234', test_fixture: true})")

    event = {
        "Records": [
            _sns_record(
                {
                    "message_type": "node_write",
                    "label": "CVE",
                    "key": {"cve_id": "CVE-2026-1234"},
                    "changed_fields": ["cvss_score"],
                    "event_time": "2026-08-11T12:00:00+00:00",
                }
            )
        ]
    }
    result = handler(event, None)
    assert result["processed"] == 1

    with driver.session() as session:
        record = session.run(
            "MATCH (c:CVE {cve_id: 'CVE-2026-1234'}) RETURN c.last_updated AS lu"
        ).single()
    assert record["lu"] == datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)


def test_edge_write_stamps_last_updated_on_the_edge(driver):
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-2026-1234', test_fixture: true})"
            "-[:EXPLOITED_BY {confidence: 0.5}]->"
            "(:ThreatActor {merge_key: 'lazarus', test_fixture: true})"
        )

    event = {
        "Records": [
            _sns_record(
                {
                    "message_type": "edge_write",
                    "rel_type": "EXPLOITED_BY",
                    "start_label": "CVE",
                    "start_key": {"cve_id": "CVE-2026-1234"},
                    "end_label": "ThreatActor",
                    "end_key": {"merge_key": "lazarus"},
                    "outcome": "created",
                    "event_time": "2026-08-11T12:00:00+00:00",
                }
            )
        ]
    }
    result = handler(event, None)
    assert result["processed"] == 1

    with driver.session() as session:
        record = session.run(
            "MATCH (:CVE {cve_id: 'CVE-2026-1234'})-[r:EXPLOITED_BY]->"
            "(:ThreatActor {merge_key: 'lazarus'}) RETURN r.last_updated AS lu"
        ).single()
    assert record["lu"] == datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)


def test_article_message_stamps_last_updated(driver):
    with driver.session() as session:
        session.run(
            "CREATE (:Article {source_guid_key: 'src1::guid1', title: 'x', "
            "test_fixture: true})"
        )

    event = {
        "Records": [
            _sns_record(
                {
                    "message_type": "article",
                    "node_label": "Article",
                    "article_id": "src1::guid1",
                    "source_id": "src1",
                    "guid": "guid1",
                    "cleaned_text": "...",
                    "title": "x",
                    "published_at": "2026-08-11T12:00:00+00:00",
                }
            )
        ]
    }
    result = handler(event, None)
    assert result["processed"] == 1

    with driver.session() as session:
        record = session.run(
            "MATCH (a:Article {source_guid_key: 'src1::guid1'}) RETURN a.last_updated AS lu"
        ).single()
    assert record["lu"] is not None


def test_unknown_message_type_is_skipped_not_raised():
    event = {"Records": [_sns_record({"message_type": "something_else"})]}
    result = handler(event, None)
    assert result == {"processed": 0, "skipped": 1}
