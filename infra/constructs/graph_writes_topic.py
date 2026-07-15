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

    def subscribe_lambda(self, id: str, fn: _lambda.IFunction) -> None:
        self.topic.add_subscription(subs.LambdaSubscription(fn))
