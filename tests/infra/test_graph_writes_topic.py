import aws_cdk as cdk
from aws_cdk import Stack, aws_lambda as _lambda
from aws_cdk.assertions import Template

from infra.constructs.graph_writes_topic import GraphWritesTopic


def _test_stack() -> Stack:
    app = cdk.App()
    return Stack(app, "TestStack")


def _dummy_lambda(stack: Stack, construct_id: str) -> _lambda.Function:
    return _lambda.Function(
        stack,
        construct_id,
        runtime=_lambda.Runtime.PYTHON_3_12,
        handler="handler.main",
        code=_lambda.Code.from_inline("def main(event, context): pass"),
    )


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
    topic_construct.subscribe_lambda(fn)

    template = Template.from_stack(stack)
    template.resource_count_is("AWS::SNS::Subscription", 1)


def test_subscribe_lambda_attaches_a_filter_policy():
    """An unattached filter policy fails OPEN and is invisible at runtime -- the
    subscriber just quietly receives everything. Assert on the synthesized template."""
    app = cdk.App()
    stack = cdk.Stack(app, "T")
    topic = GraphWritesTopic(stack, "Topic")
    fn = _dummy_lambda(stack, "Fn")

    topic.subscribe_lambda(fn, message_types=["edge_write", "node_write"])

    Template.from_stack(stack).has_resource_properties(
        "AWS::SNS::Subscription",
        {"FilterPolicy": {"message_type": ["edge_write", "node_write"]}},
    )


def test_subscribe_lambda_without_message_types_has_no_filter_policy():
    """Backwards compatible: an unfiltered subscription must stay unfiltered."""
    app = cdk.App()
    stack = cdk.Stack(app, "T")
    topic = GraphWritesTopic(stack, "Topic")
    topic.subscribe_lambda(_dummy_lambda(stack, "Fn"))

    subs = Template.from_stack(stack).find_resources("AWS::SNS::Subscription")
    # This project has been burned by this exact vacuous-pass shape before (see
    # CLAUDE.md's L1 final-review Important #3): `all(...)` over an empty dict is True,
    # so a subscription that failed to synthesize at all would pass silently.
    assert subs
    assert all("FilterPolicy" not in s["Properties"] for s in subs.values())
