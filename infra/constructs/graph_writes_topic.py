from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as subs
from constructs import Construct


class GraphWritesTopic(Construct):
    def __init__(
        self, scope: Construct, construct_id: str, *, topic_name: str = "graph-writes"
    ) -> None:
        super().__init__(scope, construct_id)
        self.topic = sns.Topic(self, "Topic", topic_name=topic_name)

    def subscribe_lambda(
        self, fn: _lambda.IFunction, *, message_types: list[str] | None = None
    ) -> None:
        """Subscribe `fn` to the graph-writes topic, optionally filtered by message_type.

        No `id` param: `LambdaSubscription` derives the subscription's construct id from `fn`
        itself, so there is nothing for a caller-supplied id to name. An earlier signature took
        one and ignored it.

        `message_types=None` means unfiltered -- the subscriber receives every message,
        including future types it may not understand. Prefer an explicit allowlist.

        DEPLOY ORDER: a filter policy drops any message whose `message_type` attribute is
        missing, so every publisher must stamp the attribute (see
        src/common/graph/publish.py) BEFORE a filtered subscription goes live.
        """
        filter_policy = None
        if message_types is not None:
            filter_policy = {
                "message_type": sns.SubscriptionFilter.string_filter(
                    allowlist=message_types
                )
            }
        self.topic.add_subscription(
            subs.LambdaSubscription(fn, filter_policy=filter_policy)
        )
