"""Tests for src.collection.rss.dedup_state (DedupState/PollingState DynamoDB access).

FR-DC-09/10/11: dedup state (content fingerprint per (source_id, guid)) backs the
poll-and-decide-whether-to-publish logic.
FR-DC-14: polling health state (consecutive_failures, last_success_at) per source_id.
"""

import boto3
import pytest
from moto import mock_aws

from src.collection.rss.dedup_state import (
    get_fingerprint,
    put_fingerprint,
    record_poll_outcome,
)


@pytest.fixture
def aws_credentials(monkeypatch):
    """Moto needs a region and dummy credentials; the production module takes an
    injected table and opens no client of its own, so nothing here leaks into it."""
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")


@pytest.fixture
def dedup_table(aws_credentials):
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="DedupState",
            KeySchema=[
                {"AttributeName": "source_id", "KeyType": "HASH"},
                {"AttributeName": "guid", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "source_id", "AttributeType": "S"},
                {"AttributeName": "guid", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table


@pytest.fixture
def polling_table(aws_credentials):
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="PollingState",
            KeySchema=[
                {"AttributeName": "source_id", "KeyType": "HASH"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "source_id", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table


def test_get_fingerprint_unseen_key_returns_none(dedup_table):
    """FR-DC-09: a never-seen (source_id, guid) must be treated as a new discovery."""
    result = get_fingerprint(dedup_table, "source-1", "guid-unseen")
    assert result is None


def test_put_then_get_fingerprint_round_trips(dedup_table):
    """FR-DC-10: a stored fingerprint must be retrievable to detect unchanged content."""
    put_fingerprint(dedup_table, "source-1", "guid-1", "abc123fingerprint")
    result = get_fingerprint(dedup_table, "source-1", "guid-1")
    assert result == "abc123fingerprint"


def test_record_poll_outcome_tracks_consecutive_failures_and_last_success(polling_table):
    """FR-DC-14: consecutive_failures increments on failure, resets to 0 on success;
    last_success_at is only set on a success."""
    source_id = "source-1"

    record_poll_outcome(polling_table, source_id, success=False)
    item = polling_table.get_item(Key={"source_id": source_id})["Item"]
    assert item["consecutive_failures"] == 1
    assert "last_success_at" not in item

    record_poll_outcome(polling_table, source_id, success=False)
    item = polling_table.get_item(Key={"source_id": source_id})["Item"]
    assert item["consecutive_failures"] == 2
    assert "last_success_at" not in item

    record_poll_outcome(polling_table, source_id, success=False)
    item = polling_table.get_item(Key={"source_id": source_id})["Item"]
    assert item["consecutive_failures"] == 3
    assert "last_success_at" not in item

    record_poll_outcome(polling_table, source_id, success=True)
    item = polling_table.get_item(Key={"source_id": source_id})["Item"]
    assert item["consecutive_failures"] == 0
    assert "last_success_at" in item
