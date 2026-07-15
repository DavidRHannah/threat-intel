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

    def subscribe_lambda(self, fn: _lambda.IFunction) -> None:
        """Subscribe `fn` to the graph-writes topic.

        No `id` param: `LambdaSubscription` derives the subscription's construct id from `fn`
        itself, so there is nothing for a caller-supplied id to name. An earlier signature took
        one and ignored it.
        """
        self.topic.add_subscription(subs.LambdaSubscription(fn))
