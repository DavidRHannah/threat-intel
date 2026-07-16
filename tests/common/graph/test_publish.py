# No dedicated FR-ID: this covers the §5 messaging-topology contract (the `graph-writes`
# SNS publish hook), not a functional requirement.
import json

import boto3
from moto import mock_aws

from src.common.config import get_config
from src.common.graph.publish import publish_graph_write


@mock_aws
def test_publish_sends_message_to_configured_topic(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")

    sns = boto3.client("sns", region_name="us-east-1")
    topic_arn = sns.create_topic(Name="graph-writes")["TopicArn"]
    monkeypatch.setenv("CROSSROADS_GRAPH_WRITES_TOPIC_ARN", topic_arn)
    get_config.cache_clear()

    sqs = boto3.client("sqs", region_name="us-east-1")
    queue_url = sqs.create_queue(QueueName="probe")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

    publish_graph_write(
        rel_type="EXPLOITED_BY",
        start_key={"cve_id": "CVE-2026-0005"},
        end_key={"merge_key": "apt-pub-test"},
        outcome="created",
        origin="inferred",
    )

    messages = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1)["Messages"]
    body = json.loads(json.loads(messages[0]["Body"])["Message"])
    assert body["rel_type"] == "EXPLOITED_BY"
    assert body["outcome"] == "created"

    get_config.cache_clear()
