import aws_cdk as cdk
from aws_cdk import Stack, aws_lambda as _lambda
from aws_cdk.assertions import Template

from infra.constructs.graph_writes_topic import GraphWritesTopic


def _test_stack() -> Stack:
    app = cdk.App()
    return Stack(app, "TestStack")


def test_creates_topic_with_expected_name():
    stack = _test_stack()
    GraphWritesTopic(stack, "GraphWrites")

    template = Template.from_stack(stack)
    template.has_resource_properties("AWS::SNS::Topic", {"TopicName": "graph-writes"})


def test_subscribe_lambda_adds_subscription():
    stack = _test_stack()
    topic_construct = GraphWritesTopic(stack, "GraphWrites")
    fn = _lambda.Function(
        stack,
        "Scoring",
        runtime=_lambda.Runtime.PYTHON_3_12,
        handler="handler.main",
        code=_lambda.Code.from_inline("def main(event, context): pass"),
    )
    topic_construct.subscribe_lambda("ScoringSub", fn)

    template = Template.from_stack(stack)
    template.resource_count_is("AWS::SNS::Subscription", 1)
