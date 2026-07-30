import json
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from src.nlp.extraction.handler import handler


@pytest.fixture(autouse=True)
def _raw_mentions_queue_url(monkeypatch):
    monkeypatch.setenv("CROSSROADS_RAW_MENTIONS_QUEUE_URL", "https://sqs.example/raw-mentions")
    yield


def _sns_event(*messages):
    return {
        "Records": [
            {"Sns": {"Message": json.dumps(message)}} for message in messages
        ]
    }


ARTICLE_MESSAGE = {
    "node_label": "Article",
    "article_id": "a1",
    "source_id": "s1",
    "guid": "g1",
    "cleaned_text": "Attackers exploited CVE-2026-1234. Fancy Bear was observed using it.",
    "title": "Fancy Bear exploits CVE-2026-1234",
    "published_at": "2026-01-01T00:00:00Z",
}


def _mock_fuzzy_response(candidates):
    resp = MagicMock()
    block = MagicMock(type="tool_use", input={"candidates": candidates})
    resp.content = [block]
    resp.stop_reason = "tool_use"
    return resp


@patch("src.nlp.extraction.handler.boto3")
@patch("src.nlp.extraction.handler.extract_fuzzy")
def test_article_event_emits_both_deterministic_and_fuzzy_mentions(mock_extract_fuzzy, mock_boto3):
    from src.nlp.messages import RawMention

    mock_extract_fuzzy.return_value = [
        RawMention(
            article_id="", entity_type="threat_actor", surface_text="Fancy Bear",
            char_span=(0, 10), extraction_confidence=0.9, context_snippet="Fancy Bear",
        )
    ]
    mock_sqs = MagicMock()
    mock_boto3.client.return_value = mock_sqs

    event = _sns_event(ARTICLE_MESSAGE)
    handler(event, None)

    assert mock_sqs.send_message.called
    body = json.loads(mock_sqs.send_message.call_args.kwargs["MessageBody"])
    entity_types = {m["entity_type"] for m in body["mentions"]}
    assert "cve" in entity_types
    assert "threat_actor" in entity_types
    # C1: title/published_at must be carried through to the raw-mentions SQS body --
    # Resolution reads them straight from this message, no default placeholder.
    assert body["title"] == ARTICLE_MESSAGE["title"]
    assert body["published_at"] == ARTICLE_MESSAGE["published_at"]


@patch("src.nlp.extraction.handler.boto3")
@patch("src.nlp.extraction.handler.extract_fuzzy")
def test_non_article_record_is_skipped_without_error(mock_extract_fuzzy, mock_boto3):
    mock_sqs = MagicMock()
    mock_boto3.client.return_value = mock_sqs

    event = _sns_event({"node_label": "IOC", "value": "1.2.3.4"})
    result = handler(event, None)

    assert not mock_extract_fuzzy.called
    assert not mock_sqs.send_message.called
    assert result is not None


@patch("src.nlp.extraction.handler.boto3")
@patch("src.nlp.extraction.handler.extract_fuzzy")
def test_llm_failure_still_publishes_deterministic_mentions(mock_extract_fuzzy, mock_boto3):
    mock_extract_fuzzy.side_effect = TimeoutError("simulated timeout")
    mock_sqs = MagicMock()
    mock_boto3.client.return_value = mock_sqs

    event = _sns_event(ARTICLE_MESSAGE)
    handler(event, None)  # must not raise

    assert mock_sqs.send_message.called
    body = json.loads(mock_sqs.send_message.call_args.kwargs["MessageBody"])
    entity_types = {m["entity_type"] for m in body["mentions"]}
    assert "cve" in entity_types
    assert "threat_actor" not in entity_types


@patch("src.nlp.extraction.handler.boto3")
@patch("src.nlp.extraction.handler.extract_fuzzy")
def test_same_article_processed_twice_yields_identical_deterministic_mentions(
    mock_extract_fuzzy, mock_boto3
):
    mock_extract_fuzzy.return_value = []
    mock_sqs = MagicMock()
    mock_boto3.client.return_value = mock_sqs

    event = _sns_event(ARTICLE_MESSAGE)
    handler(event, None)
    handler(event, None)

    bodies = [
        json.loads(call.kwargs["MessageBody"]) for call in mock_sqs.send_message.call_args_list
    ]
    assert bodies[0]["mentions"] == bodies[1]["mentions"]


def test_handler_module_never_imports_neo4j():
    """FR-EX-12: extraction never touches Neo4j.

    Verified by running the handler module in a clean subprocess and
    asserting neo4j never enters sys.modules -- a static grep-based check
    would miss a dynamic/indirect import.
    """
    script = (
        "import sys\n"
        "import src.nlp.extraction.handler\n"
        "assert 'neo4j' not in sys.modules, sys.modules.keys()\n"
        "assert not any('common.neo4j_driver' in m or 'common.graph' in m for m in sys.modules)\n"
        "print('OK')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=".",
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK" in result.stdout
