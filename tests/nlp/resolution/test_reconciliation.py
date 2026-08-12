from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

from src.common.config import get_config
from src.common.neo4j_driver import close_driver, get_driver
from src.nlp.resolution.reconciliation import reconcile


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
def review_queue_table(aws_credentials, monkeypatch):
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="crossroads-test-reconciliationreviewqueue",
            KeySchema=[
                {"AttributeName": "provisional_merge_key", "KeyType": "HASH"},
                {"AttributeName": "candidate_merge_key", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "provisional_merge_key", "AttributeType": "S"},
                {"AttributeName": "candidate_merge_key", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        monkeypatch.setenv(
            "CROSSROADS_RECONCILIATION_REVIEW_QUEUE_TABLE_NAME",
            "crossroads-test-reconciliationreviewqueue",
        )
        get_config.cache_clear()
        yield table
        get_config.cache_clear()


# FR-RES-08, FR-RES-10: exact-normalized-alias match auto-merges, re-points
# edges, folds the name into aliases, and deletes the provisional node.
def test_reconcile_exact_alias_match_merges_provisional_into_canonical(
    driver, review_queue_table
):
    with driver.session() as s:
        s.run(
            "MERGE (p:ThreatActor:Provisional {merge_key: 'scattered spider'}) "
            "SET p.test_fixture = true, p.name = 'Scattered Spider', "
            "p.aliases = ['Scattered Spider'], p.mitre_id = null, p.confidence = 0.8"
        ).consume()
        s.run(
            "MERGE (c:ThreatActor {merge_key: 'G1015'}) "
            "SET c.test_fixture = true, c.mitre_id = 'G1015', c.name = 'Scattered Spider', "
            "c.aliases = ['Scattered Spider']"
        ).consume()
        s.run(
            "MERGE (a:Article {source_guid_key: 'recon-test::guid-1'}) "
            "SET a.test_fixture = true "
            "WITH a "
            "MATCH (p:ThreatActor:Provisional {merge_key: 'scattered spider'}) "
            "MERGE (a)-[:MENTIONS]->(p)"
        ).consume()

    result = reconcile(driver, canonical_merge_key="G1015", canonical_label="ThreatActor")

    assert result.merged is True
    assert "scattered spider" in result.merged_provisional_keys

    with driver.session() as s:
        provisional_count = s.run(
            "MATCH (p:Provisional {merge_key: 'scattered spider'}) RETURN count(p) AS c"
        ).single()["c"]
        assert provisional_count == 0

        edge_count = s.run(
            "MATCH (:Article {source_guid_key: 'recon-test::guid-1'})-[r:MENTIONS]->"
            "(:ThreatActor {merge_key: 'G1015'}) RETURN count(r) AS c"
        ).single()["c"]
        assert edge_count == 1

        canonical = s.run(
            "MATCH (c:ThreatActor {merge_key: 'G1015'}) RETURN c.aliases AS aliases"
        ).single()
        assert "Scattered Spider" in canonical["aliases"]


# FR-RES-09: a near-but-inexact match writes a review-queue row and merges nothing.
def test_reconcile_fuzzy_match_writes_review_queue_row_and_does_not_merge(
    driver, review_queue_table
):
    with driver.session() as s:
        s.run(
            "MERGE (p:ThreatActor:Provisional {merge_key: 'scattered spyder'}) "
            "SET p.test_fixture = true, p.name = 'Scattered Spyder', "
            "p.aliases = ['Scattered Spyder'], p.mitre_id = null, p.confidence = 0.6"
        ).consume()
        s.run(
            "MERGE (c:ThreatActor {merge_key: 'G1015'}) "
            "SET c.test_fixture = true, c.mitre_id = 'G1015', c.name = 'Scattered Spider', "
            "c.aliases = ['Scattered Spider']"
        ).consume()

    result = reconcile(driver, canonical_merge_key="G1015", canonical_label="ThreatActor")

    assert result.merged is False
    assert "scattered spyder" in result.queued_for_review

    with driver.session() as s:
        provisional_count = s.run(
            "MATCH (p:Provisional {merge_key: 'scattered spyder'}) RETURN count(p) AS c"
        ).single()["c"]
        assert provisional_count == 1

    item = review_queue_table.get_item(
        Key={"provisional_merge_key": "scattered spyder", "candidate_merge_key": "G1015"}
    ).get("Item")
    assert item is not None


def test_reconcile_unrelated_provisional_is_left_alone(driver, review_queue_table):
    with driver.session() as s:
        s.run(
            "MERGE (p:ThreatActor:Provisional {merge_key: 'completely different actor'}) "
            "SET p.test_fixture = true, p.name = 'Completely Different Actor', "
            "p.aliases = ['Completely Different Actor'], p.mitre_id = null, p.confidence = 0.6"
        ).consume()
        s.run(
            "MERGE (c:ThreatActor {merge_key: 'G1015'}) "
            "SET c.test_fixture = true, c.mitre_id = 'G1015', c.name = 'Scattered Spider', "
            "c.aliases = ['Scattered Spider']"
        ).consume()

    result = reconcile(driver, canonical_merge_key="G1015", canonical_label="ThreatActor")

    assert result.merged is False
    assert result.merged_provisional_keys == []
    assert result.queued_for_review == []

    with driver.session() as s:
        provisional_count = s.run(
            "MATCH (p:Provisional {merge_key: 'completely different actor'}) RETURN count(p) AS c"
        ).single()["c"]
        assert provisional_count == 1


@patch("src.nlp.resolution.reconciliation.publish_node_merge")
def test_merge_of_exported_provisional_publishes_node_merge(mock_publish, driver):
    with driver.session() as s:
        s.run(
            "MERGE (c:ThreatActor {merge_key: 'G1015'}) "
            "SET c.test_fixture = true, c.mitre_id = 'G1015', c.name = 'Scattered Spider', "
            "c.aliases = ['Scattered Spider']"
        ).consume()
        s.run(
            "MERGE (p:ThreatActor:Provisional {merge_key: 'scattered spider'}) "
            "SET p.test_fixture = true, p.name = 'Scattered Spider', "
            "p.aliases = ['Scattered Spider'], p.mitre_id = null, p.confidence = 0.8, "
            "p.exported = true"
        ).consume()

    result = reconcile(driver, canonical_merge_key="G1015", canonical_label="ThreatActor")

    assert result.merged is True
    mock_publish.assert_called_once_with(
        label="ThreatActor",
        old_key={"merge_key": "scattered spider"},
        new_key={"merge_key": "G1015"},
    )


@patch("src.nlp.resolution.reconciliation.publish_node_merge")
def test_merge_of_never_exported_provisional_publishes_nothing(mock_publish, driver):
    with driver.session() as s:
        s.run(
            "MERGE (c:ThreatActor {merge_key: 'G1015'}) "
            "SET c.test_fixture = true, c.mitre_id = 'G1015', c.name = 'Scattered Spider', "
            "c.aliases = ['Scattered Spider']"
        ).consume()
        s.run(
            "MERGE (p:ThreatActor:Provisional {merge_key: 'scattered spider'}) "
            "SET p.test_fixture = true, p.name = 'Scattered Spider', "
            "p.aliases = ['Scattered Spider'], p.mitre_id = null, p.confidence = 0.8"
            # no `exported` property at all
        ).consume()

    reconcile(driver, canonical_merge_key="G1015", canonical_label="ThreatActor")

    mock_publish.assert_not_called()
