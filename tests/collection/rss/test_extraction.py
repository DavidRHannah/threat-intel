"""Tests for the RSS/Atom Extraction Lambda (L1 Task 5).

FR-DC-12 (Must): full-text extraction of the fetched article populates
`cleaned_text` with real content and `is_fallback_content = False`.
FR-DC-13 (Must): a permanently-failing fetch never drops the article; it falls
back to the discovery event's own `summary` as `cleaned_text`, flagged
`is_fallback_content = True`.
FR-DC-01 (Must, for Article): processing the same discovery event twice
results in exactly one Article node (idempotent MERGE on `source_guid_key`).

Integration tests against real local Neo4j (`docker compose up -d neo4j`).
The page fetch is mocked via an injected `fetch_page_fn` — never hits the
live internet. The SNS client is a fake collecting `publish` calls.
"""

import json

import pytest

from src.collection.rss.extraction import handler
from src.common import natural_keys
from src.common.neo4j_driver import close_driver, get_driver
from src.common.schema_bootstrap import bootstrap_schema


def _discovery_event(source_id="src-1", guid="guid-1", **overrides):
    payload = {
        "event_type": "discovery",
        "source_id": source_id,
        "guid": guid,
        "title": "Some Threat Report",
        "summary": "A summary of the threat report.",
        "link": "https://example.com/threat-report",
        "published_at": "2026-07-18T00:00:00+00:00",
        "fetched_at": "2026-07-18T00:00:05+00:00",
    }
    payload.update(overrides)
    return {"Records": [{"body": json.dumps(payload)}]}


class FakeSNSClient:
    def __init__(self):
        self.published = []

    def publish(self, *, TopicArn, Message):
        self.published.append({"TopicArn": TopicArn, "Message": json.loads(Message)})


@pytest.fixture
def driver():
    d = get_driver()
    d.verify_connectivity()
    bootstrap_schema(d)
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


def _mark_test_fixture(driver, source_guid_key):
    with driver.session() as s:
        s.run(
            "MATCH (a:Article {source_guid_key: $key}) SET a.test_fixture = true",
            key=source_guid_key,
        ).consume()


def test_full_text_extraction_populates_cleaned_text(driver, monkeypatch):
    monkeypatch.setenv("CROSSROADS_GRAPH_WRITES_TOPIC_ARN", "arn:aws:sns:us-east-1:123:graph-writes")
    event = _discovery_event(source_id="src-1", guid="guid-1")
    sns = FakeSNSClient()

    def fetch_page_fn(url):
        assert url == "https://example.com/threat-report"
        return "This is the full cleaned article text extracted from the page."

    handler(event, None, fetch_page_fn=fetch_page_fn, sns_client=sns)

    key = natural_keys.article_key("src-1", "guid-1")
    _mark_test_fixture(driver, key)
    with driver.session() as s:
        record = s.run(
            "MATCH (a:Article {source_guid_key: $key}) RETURN a AS a", key=key
        ).single()
    assert record is not None
    article = record["a"]
    assert article["cleaned_text"] == "This is the full cleaned article text extracted from the page."
    assert article["is_fallback_content"] is False


def test_permanent_fetch_failure_falls_back_to_summary(driver, monkeypatch):
    monkeypatch.setenv("CROSSROADS_GRAPH_WRITES_TOPIC_ARN", "arn:aws:sns:us-east-1:123:graph-writes")
    event = _discovery_event(source_id="src-2", guid="guid-2", summary="The fallback summary text.")
    sns = FakeSNSClient()

    def fetch_page_fn(url):
        raise RuntimeError("permanent fetch failure")

    handler(event, None, fetch_page_fn=fetch_page_fn, sns_client=sns)

    key = natural_keys.article_key("src-2", "guid-2")
    _mark_test_fixture(driver, key)
    with driver.session() as s:
        record = s.run(
            "MATCH (a:Article {source_guid_key: $key}) RETURN a AS a", key=key
        ).single()
    assert record is not None
    article = record["a"]
    assert article["cleaned_text"] == "The fallback summary text."
    assert article["is_fallback_content"] is True


def test_same_event_processed_twice_yields_one_article(driver, monkeypatch):
    monkeypatch.setenv("CROSSROADS_GRAPH_WRITES_TOPIC_ARN", "arn:aws:sns:us-east-1:123:graph-writes")
    event = _discovery_event(source_id="src-3", guid="guid-3")
    sns = FakeSNSClient()

    def fetch_page_fn(url):
        return "Full clean text."

    handler(event, None, fetch_page_fn=fetch_page_fn, sns_client=sns)
    handler(event, None, fetch_page_fn=fetch_page_fn, sns_client=sns)

    key = natural_keys.article_key("src-3", "guid-3")
    _mark_test_fixture(driver, key)
    with driver.session() as s:
        count = s.run(
            "MATCH (a:Article {source_guid_key: $key}) RETURN count(a) AS c", key=key
        ).single()["c"]
    assert count == 1


def test_sns_publish_carries_node_shaped_article_payload(driver, monkeypatch):
    monkeypatch.setenv("CROSSROADS_GRAPH_WRITES_TOPIC_ARN", "arn:aws:sns:us-east-1:123:graph-writes")
    event = _discovery_event(source_id="src-4", guid="guid-4")
    sns = FakeSNSClient()

    def fetch_page_fn(url):
        return "Clean article body for publish test."

    handler(event, None, fetch_page_fn=fetch_page_fn, sns_client=sns)

    key = natural_keys.article_key("src-4", "guid-4")
    _mark_test_fixture(driver, key)

    assert len(sns.published) == 1
    message = sns.published[0]["Message"]
    assert message["node_label"] == "Article"
    assert message["article_id"] == key
    assert message["article_id"] == natural_keys.article_key("src-4", "guid-4")
    assert message["source_id"] == "src-4"
    assert message["guid"] == "guid-4"
    assert message["cleaned_text"] == "Clean article body for publish test."
    assert message["title"] == "Some Threat Report"
    assert message["published_at"] == "2026-07-18T00:00:00+00:00"
    assert sns.published[0]["TopicArn"] == "arn:aws:sns:us-east-1:123:graph-writes"
