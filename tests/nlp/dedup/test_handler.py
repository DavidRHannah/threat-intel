"""Tests for Step 3.3 of `plans/02-nlp.md`: the Dedup Lambda handler --
re-emission of `StoryCluster` on membership change (FR-DED-07), and
determinism across repeated runs (FR-DED-08).

Integration -- mirrors the `driver` fixture pattern in
`tests/nlp/resolution/test_handler.py` / `tests/nlp/dedup/test_clustering.py`.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.nlp.dedup.handler import _process_article, handler
from src.nlp.messages import ResolvedArticle, ResolvedEntity, StoryCluster

BASE_TIME = datetime(2026, 7, 1, tzinfo=timezone.utc)


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


@pytest.fixture(autouse=True)
def _story_clusters_queue_url(monkeypatch):
    monkeypatch.setenv(
        "CROSSROADS_STORY_CLUSTERS_QUEUE_URL", "https://sqs.example/story-clusters"
    )


class FakeSqsClient:
    """Minimal stub recording `send_message` calls, matching the fake pattern
    used across the resolution handler tests (there via `MagicMock`; here a
    dedicated stub since we need to inspect multiple calls in order)."""

    def __init__(self):
        self.sent: list[dict] = []

    def send_message(self, *, QueueUrl: str, MessageBody: str):
        self.sent.append({"QueueUrl": QueueUrl, "MessageBody": MessageBody})


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _make_article(
    driver,
    *,
    key: str,
    published_at: str,
    content_hash: str = "",
    cleaned_text: str = "",
    cve_id: str | None = None,
) -> None:
    with driver.session() as s:
        s.run(
            "MERGE (a:Article {source_guid_key: $key}) "
            "SET a.test_fixture = true, a.published_at = $published_at, "
            "a.content_hash = $content_hash, a.cleaned_text = $cleaned_text, "
            "a.source_id = $source_id, a.guid = $guid",
            key=key,
            published_at=published_at,
            content_hash=content_hash,
            cleaned_text=cleaned_text,
            source_id=key.split("::")[0],
            guid=key.split("::")[1],
        ).consume()
        if cve_id:
            s.run(
                "MERGE (c:CVE {cve_id: $cve_id}) SET c.test_fixture = true "
                "WITH c MATCH (a:Article {source_guid_key: $key}) "
                "MERGE (a)-[:MENTIONS]->(c)",
                cve_id=cve_id,
                key=key,
            ).consume()


def _resolved_article_message(
    key: str, published_at: str, cve_id: str | None = None
) -> dict:
    entities = (
        [
            ResolvedEntity(
                canonical_node_key=cve_id,
                entity_type="cve",
                resolution_status="resolved",
                node_confidence=0.95,
            )
        ]
        if cve_id
        else []
    )
    return ResolvedArticle(
        article_id=key,
        title="title",
        published_at=published_at,
        source_id=key.split("::")[0],
        resolved_entities=entities,
    ).to_dict()


# FR-DED-07: a new member joining a cluster triggers a StoryCluster message
# with the full updated membership.
def test_new_member_joining_cluster_emits_story_cluster_with_full_membership(driver):
    key_a = "dedup-handler-test::art-a"
    key_b = "dedup-handler-test::art-b"
    _make_article(driver, key=key_a, published_at=_iso(BASE_TIME), cve_id="CVE-2099-40001")

    sqs_client = FakeSqsClient()

    _process_article(_resolved_article_message(key_a, _iso(BASE_TIME), "CVE-2099-40001"), sqs_client, driver)

    assert len(sqs_client.sent) == 1
    first_body = json.loads(sqs_client.sent[0]["MessageBody"])
    first_cluster = StoryCluster.from_dict(first_body)
    assert first_cluster.article_ids == [key_a]

    # Second article shares the same CVE within the dedup window -> joins cluster.
    _make_article(
        driver,
        key=key_b,
        published_at=_iso(BASE_TIME + timedelta(hours=1)),
        cve_id="CVE-2099-40001",
    )
    _process_article(
        _resolved_article_message(key_b, _iso(BASE_TIME + timedelta(hours=1)), "CVE-2099-40001"),
        sqs_client,
        driver,
    )

    assert len(sqs_client.sent) == 2
    second_body = json.loads(sqs_client.sent[1]["MessageBody"])
    second_cluster = StoryCluster.from_dict(second_body)

    assert second_cluster.story_cluster_id == first_cluster.story_cluster_id
    assert sorted(second_cluster.article_ids) == sorted([key_a, key_b])

    entity_keys = {e.canonical_node_key for e in second_cluster.union_resolved_entities}
    assert entity_keys == {"CVE-2099-40001"}

    call_kwargs = sqs_client.sent[1]
    assert call_kwargs["QueueUrl"] == "https://sqs.example/story-clusters"


def test_union_resolved_entities_merges_across_members_dedupe_by_key(driver):
    key_a = "dedup-handler-test::union-a"
    key_b = "dedup-handler-test::union-b"
    _make_article(driver, key=key_a, published_at=_iso(BASE_TIME), cve_id="CVE-2099-40002")

    sqs_client = FakeSqsClient()
    _process_article(
        _resolved_article_message(key_a, _iso(BASE_TIME), "CVE-2099-40002"), sqs_client, driver
    )

    _make_article(
        driver,
        key=key_b,
        published_at=_iso(BASE_TIME + timedelta(hours=1)),
        cve_id="CVE-2099-40002",
    )
    message_b = _resolved_article_message(
        key_b, _iso(BASE_TIME + timedelta(hours=1)), "CVE-2099-40002"
    )
    # Give article b a higher confidence for the same canonical key.
    message_b["resolved_entities"][0]["node_confidence"] = 0.99
    _process_article(message_b, sqs_client, driver)

    body = json.loads(sqs_client.sent[-1]["MessageBody"])
    cluster = StoryCluster.from_dict(body)

    matching = [
        e for e in cluster.union_resolved_entities if e.canonical_node_key == "CVE-2099-40002"
    ]
    assert len(matching) == 1
    assert matching[0].node_confidence == 0.99


# FR-DED-08 (Should, cheap+load-bearing): same articles + thresholds run
# twice -> identical clusters (id, membership, representative).
def test_processing_same_batch_twice_is_deterministic(driver):
    key_a = "dedup-handler-test::det-a"
    key_b = "dedup-handler-test::det-b"
    _make_article(driver, key=key_a, published_at=_iso(BASE_TIME), cve_id="CVE-2099-40003")
    _make_article(
        driver,
        key=key_b,
        published_at=_iso(BASE_TIME + timedelta(hours=1)),
        cve_id="CVE-2099-40003",
    )

    event = {
        "Records": [
            {"body": json.dumps(_resolved_article_message(key_a, _iso(BASE_TIME), "CVE-2099-40003"))},
            {
                "body": json.dumps(
                    _resolved_article_message(
                        key_b, _iso(BASE_TIME + timedelta(hours=1)), "CVE-2099-40003"
                    )
                )
            },
        ]
    }

    sqs_client_1 = FakeSqsClient()
    handler(event, None, sqs_client=sqs_client_1, driver=driver)
    first_final = json.loads(sqs_client_1.sent[-1]["MessageBody"])
    first_cluster = StoryCluster.from_dict(first_final)

    sqs_client_2 = FakeSqsClient()
    handler(event, None, sqs_client=sqs_client_2, driver=driver)
    second_final = json.loads(sqs_client_2.sent[-1]["MessageBody"])
    second_cluster = StoryCluster.from_dict(second_final)

    assert first_cluster.story_cluster_id == second_cluster.story_cluster_id
    assert sorted(first_cluster.article_ids) == sorted(second_cluster.article_ids)

    with driver.session() as s:
        rep_after_first = s.run(
            "MATCH (a:Article) WHERE a.story_cluster_id = $id AND a.is_cluster_representative = true "
            "RETURN a.source_guid_key AS id",
            id=first_cluster.story_cluster_id,
        ).single()["id"]
    assert rep_after_first == key_a
