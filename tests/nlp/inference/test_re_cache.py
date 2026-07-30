"""Tests for src.nlp.inference.re_cache (RECache DynamoDB access, FR-INF-07).

RECache is keyed on the RE-target content hash: when Dedup re-emits a
StoryCluster after a non-representative member joins but the representative
article's text is unchanged, the content hash is unchanged too, so the cached
relation-extraction result can be reused instead of re-calling the LLM.
"""

import boto3
import pytest
from moto import mock_aws

from src.nlp.inference.re_cache import get_cached_result, put_cached_result
from src.nlp.inference.relation_extraction import CandidateRelation


@pytest.fixture
def aws_credentials(monkeypatch):
    """Moto needs a region and dummy credentials; the production module takes an
    injected table and opens no client of its own, so nothing here leaks into it."""
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")


@pytest.fixture
def re_cache_table(aws_credentials):
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="RECache",
            KeySchema=[
                {"AttributeName": "re_target_content_hash", "KeyType": "HASH"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "re_target_content_hash", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table


def _candidate() -> CandidateRelation:
    return CandidateRelation(
        entity_a={"canonical_node_key": "cve:CVE-2024-1234", "entity_type": "cve"},
        entity_b={"canonical_node_key": "actor:apt-1", "entity_type": "threat_actor"},
        relationship="exploited by",
        direction="a_to_b",
        assertion_strength=0.9,
        polarity="asserted",
    )


def test_get_cached_result_unseen_hash_returns_none(re_cache_table):
    """A never-cached content hash is a cache miss (None), not an error."""
    result = get_cached_result(re_cache_table, "unseen-content-hash")
    assert result is None


def test_re_emitted_cluster_with_unchanged_text_is_a_cache_hit(re_cache_table):
    """FR-INF-07: a StoryCluster re-emitted after a non-representative member
    joins, whose RE-target text (and therefore content hash) is unchanged,
    must be served from the cache -- no new LLM call needed by the caller."""
    content_hash = "sha256-representative-article-text-unchanged"
    relations = [_candidate()]

    put_cached_result(re_cache_table, content_hash, relations)

    cached = get_cached_result(re_cache_table, content_hash)

    assert cached is not None
    assert cached == relations
