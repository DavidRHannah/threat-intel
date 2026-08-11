"""The graph-writes message contract (technical-specification.md §5).

Every publisher must stamp `message_type`, because Task 1.3 attaches SNS subscription
filter policies keyed on it -- and a filter policy drops any message missing the
attribute it filters on.
"""
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.common.config import get_config
from src.common.graph.publish import (
    MESSAGE_TYPE_ARTICLE,
    MESSAGE_TYPE_EDGE_WRITE,
    MESSAGE_TYPE_NODE_WRITE,
    publish_graph_write,
    publish_node_write,
)


@pytest.fixture(autouse=True)
def _clear_config_cache():
    # Every test here sets CROSSROADS_GRAPH_WRITES_TOPIC_ARN via monkeypatch and reads
    # it through the lru_cached get_config -- clearing on exit too (not just entry)
    # keeps that env-dependent value from leaking into whichever test runs next.
    get_config.cache_clear()
    yield
    get_config.cache_clear()


def _attr(call):
    return call.kwargs["MessageAttributes"]["message_type"]["StringValue"]


@patch("boto3.client")
def test_edge_write_stamps_its_message_type(mock_client, monkeypatch):
    monkeypatch.setenv("CROSSROADS_GRAPH_WRITES_TOPIC_ARN", "arn:aws:sns:x:1:graph-writes")
    sns = MagicMock()
    mock_client.return_value = sns

    publish_graph_write(
        rel_type="EXPLOITED_BY", start_key={"cve_id": "CVE-2026-1"},
        end_key={"merge_key": "apt-x"}, outcome="created", origin="inferred",
    )
    call = sns.publish.call_args
    assert _attr(call) == MESSAGE_TYPE_EDGE_WRITE == "edge_write"
    assert json.loads(call.kwargs["Message"])["rel_type"] == "EXPLOITED_BY"


@patch("boto3.client")
def test_node_write_carries_label_key_and_changed_fields(mock_client, monkeypatch):
    monkeypatch.setenv("CROSSROADS_GRAPH_WRITES_TOPIC_ARN", "arn:aws:sns:x:1:graph-writes")
    sns = MagicMock()
    mock_client.return_value = sns

    publish_node_write(
        label="CVE", key={"cve_id": "CVE-2026-1"},
        changed_fields=["exploited_in_wild"], origin="cisa-kev",
    )
    call = sns.publish.call_args
    assert _attr(call) == MESSAGE_TYPE_NODE_WRITE == "node_write"
    body = json.loads(call.kwargs["Message"])
    assert body == {
        "message_type": "node_write",
        "label": "CVE",
        "key": {"cve_id": "CVE-2026-1"},
        "changed_fields": ["exploited_in_wild"],
        "origin": "cisa-kev",
    }


def test_article_message_type_constant_value():
    """Pins the constant's value. Does NOT verify either L1 article publisher actually
    stamps it -- that's covered by test_sns_publish_carries_node_shaped_article_payload
    in tests/collection/rss/test_extraction.py and
    test_advisory_with_cve_creates_stub_enriches_and_publishes_article in
    tests/collection/rest/test_ghsa.py."""
    assert MESSAGE_TYPE_ARTICLE == "article"


# --- Task 5.0: the self-describing edge_write body ---------------------------------


def _publish(mock_client, monkeypatch, **kwargs):
    monkeypatch.setenv("CROSSROADS_GRAPH_WRITES_TOPIC_ARN", "arn:aws:sns:x:1:graph-writes")
    sns = MagicMock()
    mock_client.return_value = sns
    publish_graph_write(**kwargs)
    return json.loads(sns.publish.call_args.kwargs["Message"])


@patch("boto3.client")
def test_edge_write_carries_endpoint_labels(mock_client, monkeypatch):
    """`merge_key` is a lowercased NAME with PER-LABEL uniqueness, so a consumer given
    the key alone cannot tell a ThreatActor 'lazarus' from a MalwareFamily 'lazarus'."""
    body = _publish(
        mock_client, monkeypatch,
        rel_type="EXPLOITED_BY", start_key={"cve_id": "CVE-2026-1"},
        end_key={"merge_key": "lazarus"}, outcome="created", origin="inferred",
        start_label="CVE", end_label="ThreatActor",
    )
    assert body["start_label"] == "CVE"
    assert body["end_label"] == "ThreatActor"


@patch("boto3.client")
def test_edge_write_carries_the_callers_event_time(mock_client, monkeypatch):
    """Minted ONCE at publish and carried in the body, so an SNS redelivery replays the
    same instant instead of advancing the consumer's clock."""
    event_time = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)
    body = _publish(
        mock_client, monkeypatch,
        rel_type="MENTIONS", start_key={"source_guid_key": "art-1"},
        end_key={"merge_key": "lazarus"}, outcome="resolved",
        event_time=event_time,
    )
    assert body["event_time"] == event_time.isoformat()
    assert datetime.fromisoformat(body["event_time"]).tzinfo is not None


@patch("boto3.client")
def test_the_three_new_fields_are_optional(mock_client, monkeypatch):
    """BACKWARD COMPATIBILITY IS THE DESIGN: a publisher that has not been redeployed
    must still emit a valid message, so no filter policy may reference these fields."""
    body = _publish(
        mock_client, monkeypatch,
        rel_type="EXPLOITED_BY", start_key={"cve_id": "CVE-2026-1"},
        end_key={"merge_key": "apt-x"}, outcome="created", origin="inferred",
    )
    assert body["start_label"] is None
    assert body["end_label"] is None
    # event_time is self-minted rather than null: the publisher always knows "now".
    assert datetime.fromisoformat(body["event_time"]).tzinfo is not None
