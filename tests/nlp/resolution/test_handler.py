import json
from unittest.mock import MagicMock, patch

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.nlp.resolution.handler import _process_article

ARTICLE_ID = "resolution-handler-test::guid-1"


@pytest.fixture
def driver():
    d = get_driver()
    d.verify_connectivity()
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
        s.run(
            "MERGE (a:Article {source_guid_key: $key}) "
            "SET a.test_fixture = true, a.source_id = 'resolution-handler-test', "
            "a.guid = 'guid-1'",
            key=ARTICLE_ID,
        ).consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


@pytest.fixture(autouse=True)
def _resolved_articles_queue_url(monkeypatch):
    monkeypatch.setenv(
        "CROSSROADS_RESOLVED_ARTICLES_QUEUE_URL", "https://sqs.example/resolved-articles"
    )


def _mention(entity_type, surface_text, confidence=0.9):
    return {
        "article_id": ARTICLE_ID,
        "entity_type": entity_type,
        "surface_text": surface_text,
        "char_span": [0, len(surface_text)],
        "extraction_confidence": confidence,
        "context_snippet": f"...{surface_text}...",
    }


def _mark_test_fixture(driver, label, key_prop, key_value):
    with driver.session() as s:
        s.run(
            f"MATCH (n:{label} {{{key_prop}: $value}}) SET n.test_fixture = true",
            value=key_value,
        ).consume()


def _no_llm_needed():
    raise AssertionError("LLM client should not have been requested for a deterministic-only article")


@patch("src.nlp.resolution.handler.publish_graph_write")
def test_processing_same_article_twice_creates_no_duplicate_nodes_or_edges(
    mock_publish, driver
):
    message = {
        "article_id": ARTICLE_ID,
        "mentions": [_mention("cve", "CVE-2099-10001")],
    }
    sqs_client = MagicMock()

    _process_article(message, sqs_client, driver, _no_llm_needed)
    _mark_test_fixture(driver, "CVE", "cve_id", "CVE-2099-10001")
    _process_article(message, sqs_client, driver, _no_llm_needed)

    with driver.session() as s:
        node_count = s.run(
            "MATCH (c:CVE {cve_id: 'CVE-2099-10001'}) RETURN count(c) AS c"
        ).single()["c"]
        edge_count = s.run(
            "MATCH (:Article {source_guid_key: $key})-[r:MENTIONS]->"
            "(:CVE {cve_id: 'CVE-2099-10001'}) RETURN count(r) AS c",
            key=ARTICLE_ID,
        ).single()["c"]

    assert node_count == 1
    assert edge_count == 1
    assert sqs_client.send_message.call_count == 2


# FR-RES-11: a CVE removed from the new mention set has its MENTIONS edge
# retracted; a dropped actor mention is NOT retracted (additive-only).
@patch("src.nlp.resolution.handler.publish_graph_write")
def test_update_event_retracts_dropped_deterministic_mention_not_fuzzy(mock_publish, driver):
    llm_client = MagicMock()
    block = MagicMock(type="tool_use", input={"matched_merge_key": None})
    response = MagicMock()
    response.content = [block]
    llm_client.messages.create.return_value = response

    first_message = {
        "article_id": ARTICLE_ID,
        "mentions": [
            _mention("cve", "CVE-2099-20002"),
            _mention("threat_actor", "Some Novel Threat Actor"),
        ],
    }
    sqs_client = MagicMock()

    _process_article(first_message, sqs_client, driver, lambda: llm_client)
    _mark_test_fixture(driver, "CVE", "cve_id", "CVE-2099-20002")
    _mark_test_fixture(driver, "ThreatActor", "merge_key", "some novel threat actor")

    with driver.session() as s:
        cve_edge_before = s.run(
            "MATCH (:Article {source_guid_key: $key})-[r:MENTIONS]->"
            "(:CVE {cve_id: 'CVE-2099-20002'}) RETURN count(r) AS c",
            key=ARTICLE_ID,
        ).single()["c"]
        actor_edge_before = s.run(
            "MATCH (:Article {source_guid_key: $key})-[r:MENTIONS]->"
            "(:ThreatActor {merge_key: 'some novel threat actor'}) RETURN count(r) AS c",
            key=ARTICLE_ID,
        ).single()["c"]
    assert cve_edge_before == 1
    assert actor_edge_before == 1

    # Update event: the CVE is gone, the actor mention is not repeated either.
    second_message = {"article_id": ARTICLE_ID, "mentions": []}
    _process_article(second_message, sqs_client, driver, lambda: llm_client)

    with driver.session() as s:
        cve_edge_after = s.run(
            "MATCH (:Article {source_guid_key: $key})-[r:MENTIONS]->"
            "(:CVE {cve_id: 'CVE-2099-20002'}) RETURN count(r) AS c",
            key=ARTICLE_ID,
        ).single()["c"]
        actor_edge_after = s.run(
            "MATCH (:Article {source_guid_key: $key})-[r:MENTIONS]->"
            "(:ThreatActor {merge_key: 'some novel threat actor'}) RETURN count(r) AS c",
            key=ARTICLE_ID,
        ).single()["c"]

    assert cve_edge_after == 0  # retracted: deterministic type, absent from new set
    assert actor_edge_after == 1  # NOT retracted: fuzzy type is additive-only


@patch("src.nlp.resolution.handler.publish_graph_write")
def test_resolved_article_published_to_resolved_articles_queue(mock_publish, driver):
    message = {
        "article_id": ARTICLE_ID,
        "title": "Some Article Title",
        "published_at": "2026-01-01T00:00:00Z",
        "mentions": [_mention("cve", "CVE-2099-30003")],
    }
    sqs_client = MagicMock()

    _process_article(message, sqs_client, driver, _no_llm_needed)
    _mark_test_fixture(driver, "CVE", "cve_id", "CVE-2099-30003")

    sqs_client.send_message.assert_called_once()
    call_kwargs = sqs_client.send_message.call_args.kwargs
    assert call_kwargs["QueueUrl"] == "https://sqs.example/resolved-articles"
    body = json.loads(call_kwargs["MessageBody"])
    assert body["article_id"] == ARTICLE_ID
    assert body["source_id"] == "resolution-handler-test"
    assert body["resolved_entities"][0]["canonical_node_key"] == "CVE-2099-30003"
    # C1: title/published_at are read straight from the incoming message (the raw-mentions
    # SQS body Extraction now sends), never defaulted to empty string.
    assert body["title"] == "Some Article Title"
    assert body["published_at"] == "2026-01-01T00:00:00Z"


@patch("src.nlp.resolution.handler.publish_graph_write")
def test_rejected_mention_is_not_published_as_graph_write(mock_publish, driver):
    message = {
        "article_id": ARTICLE_ID,
        "mentions": [_mention("ttp", "T9999")],  # unknown TTP -> rejected
    }
    sqs_client = MagicMock()

    _process_article(message, sqs_client, driver, _no_llm_needed)

    assert not mock_publish.called
