"""End-to-end pipeline test (`plans/02-nlp.md` §5 "Full-pipeline scenario",
final-branch-review finding I2).

Chains each stage's REAL emitted message into the next stage's real input --
Extraction -> Resolution -> Dedup -> Inference -- rather than hand-constructing
each stage's input at its own boundary (every other test file's pattern).
This is deliberately the one place that exercises the actual wire shapes
stages pass each other, since that boundary is exactly where finding C1
(title/published_at silently dropped between Extraction and Resolution) lived
undetected through every stage's own test suite.

Two articles mention the same CVE and the same novel threat-actor name, far
enough apart in time (200h > the 72h dedup window) to land in two distinct
`StoryCluster`s. Each cluster's Inference pass proposes the same
`(CVE)-[:EXPLOITED_BY]->(ThreatActor)` edge at `assertion_strength=0.7`;
noisy-OR across the two distinct clusters combines to
`1 - (1-0.7)(1-0.7) = 0.91`, and `supporting_article_count == 2`.

Real Neo4j (Docker Compose) + moto DynamoDB RE-cache. The Anthropic client is
mocked at the process boundary (both stages' `get_llm_client`/`extract_fuzzy`
injection points) -- never a live API call, per every other stage's test
pattern. `publish_graph_write` is mocked in Resolution and Inference (the two
stages that call it) since it is a side-effecting SNS call, not part of the
inter-stage message chain under test here.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from src.common.neo4j_driver import close_driver, get_driver
from src.nlp.dedup.handler import _process_article as dedup_process_article
from src.nlp.extraction.handler import _process_article as extraction_process_article
from src.nlp.inference.handler import _process_story_cluster
from src.nlp.inference.relation_extraction import CandidateRelation
from src.nlp.messages import StoryCluster
from src.nlp.resolution.handler import _process_article as resolution_process_article

_TEST_PREFIX = "pipeline-e2e-test"
_CVE_ID = "CVE-2026-9999"
_ACTOR_SURFACE = "Static Kitten Two"
BASE_TIME = datetime(2026, 3, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _queue_urls(monkeypatch):
    monkeypatch.setenv("CROSSROADS_RAW_MENTIONS_QUEUE_URL", "https://sqs.example/raw-mentions")
    monkeypatch.setenv(
        "CROSSROADS_RESOLVED_ARTICLES_QUEUE_URL", "https://sqs.example/resolved-articles"
    )
    monkeypatch.setenv(
        "CROSSROADS_STORY_CLUSTERS_QUEUE_URL", "https://sqs.example/story-clusters"
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


@pytest.fixture
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")


@pytest.fixture
def re_cache_table(aws_credentials):
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="RECache",
            KeySchema=[{"AttributeName": "re_target_content_hash", "KeyType": "HASH"}],
            AttributeDefinitions=[
                {"AttributeName": "re_target_content_hash", "AttributeType": "S"}
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table


def _mark_test_fixture(driver, label, key_prop, key_value):
    with driver.session() as s:
        s.run(
            f"MATCH (n:{label} {{{key_prop}: $value}}) SET n.test_fixture = true",
            value=key_value,
        ).consume()


def _seed_article_node(driver, article_id, source_id, guid):
    # A distinct content_hash per article: Inference's RE-cache keys on this, and
    # real L1 collection always populates it (never left empty) -- Dedup's cluster
    # representative election reads it straight off the node, same as production.
    content_hash = f"hash-{guid}"
    with driver.session() as s:
        s.run(
            "MERGE (a:Article {source_guid_key: $key}) "
            "SET a.test_fixture = true, a.source_id = $source_id, a.guid = $guid, "
            "a.content_hash = $content_hash",
            key=article_id,
            source_id=source_id,
            guid=guid,
            content_hash=content_hash,
        ).consume()


def _resolution_llm_client_stub():
    """Forces tier-4 Provisional creation for the novel actor name: tiers 1/2
    find nothing in an empty alias index, and this tool_use response reports
    no match, matching `tests/nlp/resolution/test_handler.py`'s pattern."""
    client = MagicMock()
    block = MagicMock(type="tool_use", input={"matched_merge_key": None})
    response = MagicMock()
    response.content = [block]
    client.messages.create.return_value = response
    return client


def _run_extraction_through_dedup(driver, sqs_client, source_id, guid, published_at):
    article_id = f"{source_id}::{guid}"
    _seed_article_node(driver, article_id, source_id, guid)

    article_message = {
        "article_id": article_id,
        "cleaned_text": (
            f"Attackers exploited {_CVE_ID}. {_ACTOR_SURFACE} was observed using it."
        ),
        "title": f"{_ACTOR_SURFACE} exploits {_CVE_ID}",
        "published_at": published_at,
    }

    # -- Extraction: real deterministic extractor, fuzzy LLM extractor mocked.
    with patch(
        "src.nlp.extraction.handler.extract_fuzzy",
        return_value=[],
    ):
        extraction_process_article(article_message, sqs_client)

    raw_mentions_body = json.loads(sqs_client.send_message.call_args.kwargs["MessageBody"])
    # I2/C1: title and published_at must survive the Extraction -> Resolution hop.
    assert raw_mentions_body["title"] == article_message["title"]
    assert raw_mentions_body["published_at"] == published_at
    entity_types = {m["entity_type"] for m in raw_mentions_body["mentions"]}
    assert "cve" in entity_types
    # The fuzzy actor mention is patched away above (Extraction's LLM call is mocked
    # to return []) -- the actor mention is injected directly into Resolution's input
    # below instead, since exercising Extraction's own fuzzy-extraction correctness is
    # `tests/nlp/extraction/test_llm_extractor.py`'s job, not this cross-stage test's.
    actor_mention = {
        "article_id": article_id,
        "entity_type": "threat_actor",
        "surface_text": _ACTOR_SURFACE,
        "char_span": [0, len(_ACTOR_SURFACE)],
        "extraction_confidence": 0.9,
        "context_snippet": f"...{_ACTOR_SURFACE}...",
    }
    raw_mentions_body["mentions"].append(actor_mention)

    # -- Resolution: real deterministic + fuzzy resolution, publish_graph_write mocked.
    with patch("src.nlp.resolution.handler.publish_graph_write"):
        resolution_process_article(
            raw_mentions_body, sqs_client, driver, _resolution_llm_client_stub
        )
    _mark_test_fixture(driver, "CVE", "cve_id", _CVE_ID)
    _mark_test_fixture(driver, "ThreatActor", "merge_key", _ACTOR_SURFACE.lower())

    resolved_article_body = json.loads(sqs_client.send_message.call_args.kwargs["MessageBody"])
    # I2/C1: this is the exact bug C1 caused -- title/published_at defaulted to "" here
    # when Extraction dropped them, and Dedup's `_parse_timestamp("")` then raised.
    assert resolved_article_body["title"] == article_message["title"]
    assert resolved_article_body["published_at"] == published_at

    # -- Dedup: real cluster assignment.
    dedup_process_article(resolved_article_body, sqs_client, driver)
    story_cluster_body = json.loads(sqs_client.send_message.call_args.kwargs["MessageBody"])
    return StoryCluster.from_dict(story_cluster_body)


@patch("src.nlp.inference.handler.publish_graph_write")
def test_two_temporally_distant_articles_combine_via_noisy_or_across_clusters(
    mock_publish, driver, re_cache_table
):
    sqs_client = MagicMock()

    cluster_1 = _run_extraction_through_dedup(
        driver, sqs_client, _TEST_PREFIX, "article-1", _iso(BASE_TIME)
    )
    cluster_2 = _run_extraction_through_dedup(
        driver,
        sqs_client,
        _TEST_PREFIX,
        "article-2",
        _iso(BASE_TIME + timedelta(hours=200)),
    )

    # Two distinct story clusters: proves the 200h gap (> the 72h dedup window)
    # kept these as separate stories rather than merging them into one.
    assert cluster_1.story_cluster_id != cluster_2.story_cluster_id

    candidate = CandidateRelation(
        entity_a={"canonical_node_key": _ACTOR_SURFACE.lower(), "entity_type": "threat_actor"},
        entity_b={"canonical_node_key": _CVE_ID, "entity_type": "cve"},
        relationship="exploits",
        direction="b_to_a",
        assertion_strength=0.7,
        polarity="asserted",
    )

    def _get_llm_client():
        return None  # extract_relations is patched below; never actually called

    with patch(
        "src.nlp.inference.handler.extract_relations", return_value=[candidate]
    ):
        _process_story_cluster(
            cluster_1.to_dict(), driver, re_cache_table, _get_llm_client
        )
        _process_story_cluster(
            cluster_2.to_dict(), driver, re_cache_table, _get_llm_client
        )

    with driver.session() as s:
        record = s.run(
            "MATCH (c:CVE {cve_id: $cve_id})-[e:EXPLOITED_BY]->(a:ThreatActor {merge_key: $actor_key}) "
            "RETURN e.inferred_confidence AS inferred_confidence, "
            "e.supporting_article_count AS supporting_article_count, e.origin AS origin",
            cve_id=_CVE_ID,
            actor_key=_ACTOR_SURFACE.lower(),
        ).single()

    assert record is not None
    assert record["inferred_confidence"] == pytest.approx(0.91)
    assert record["supporting_article_count"] == 2
    assert "inferred" in record["origin"]


def _iso(dt: datetime) -> str:
    return dt.isoformat()
