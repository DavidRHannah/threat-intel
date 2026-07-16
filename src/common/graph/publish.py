import json

import boto3

from src.common.config import get_config


def publish_graph_write(
    *, rel_type: str, start_key: dict, end_key: dict, outcome: str, origin: str | None = None,
) -> None:
    topic_arn = get_config("graph_writes_topic_arn")
    sns = boto3.client("sns")
    sns.publish(
        TopicArn=topic_arn,
        Message=json.dumps(
            {
                "rel_type": rel_type,
                "start_key": start_key,
                "end_key": end_key,
                "outcome": outcome,
                "origin": origin,
            }
        ),
    )
