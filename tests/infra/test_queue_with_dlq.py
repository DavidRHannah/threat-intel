# tests/infra/test_queue_with_dlq.py
import aws_cdk as cdk
from aws_cdk import Stack, aws_lambda as _lambda
from aws_cdk.assertions import Match, Template

from infra.constructs.queue_with_dlq import QueueWithDlq


def _test_stack() -> Stack:
    app = cdk.App()
    return Stack(app, "TestStack")


def test_creates_queue_and_dlq_with_redrive_policy():
    stack = _test_stack()
    QueueWithDlq(stack, "RawMentions", queue_name="raw-mentions", max_receive_count=3)

    template = Template.from_stack(stack)
    template.resource_count_is("AWS::SQS::Queue", 2)
    template.has_resource_properties(
        "AWS::SQS::Queue",
        {
            "QueueName": "raw-mentions",
            "RedrivePolicy": Match.object_like({"maxReceiveCount": 3}),
        },
    )
    template.has_resource_properties("AWS::SQS::Queue", {"QueueName": "raw-mentions-dlq"})


def test_wires_consumer_lambda_as_event_source():
    stack = _test_stack()
    fn = _lambda.Function(
        stack,
        "Consumer",
        runtime=_lambda.Runtime.PYTHON_3_12,
        handler="handler.main",
        code=_lambda.Code.from_inline("def main(event, context): pass"),
    )
    QueueWithDlq(
        stack, "RawMentions", queue_name="raw-mentions", consumer=fn, batch_size=5
    )

    template = Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::Lambda::EventSourceMapping", {"BatchSize": 5}
    )
