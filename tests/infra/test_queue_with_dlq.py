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


# C3: AWS Lambda validates function timeout <= queue visibility timeout at
# CreateEventSourceMapping time -- a runtime AWS validation `cdk synth` cannot catch. A
# queue whose consumer's function timeout exceeds the construct's 60s default must not
# silently deploy-fail; the visibility timeout must be derived from the consumer.
def test_visibility_timeout_derived_from_consumer_with_long_timeout():
    stack = _test_stack()
    fn = _lambda.Function(
        stack,
        "SlowConsumer",
        runtime=_lambda.Runtime.PYTHON_3_12,
        handler="handler.main",
        code=_lambda.Code.from_inline("def main(event, context): pass"),
        timeout=cdk.Duration.minutes(5),
    )
    QueueWithDlq(stack, "StoryClusters", queue_name="story-clusters", consumer=fn)

    template = Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::SQS::Queue",
        {
            "QueueName": "story-clusters",
            "VisibilityTimeout": Match.any_value(),
        },
    )
    resources = template.find_resources("AWS::SQS::Queue", {
        "Properties": {"QueueName": "story-clusters"}
    })
    (queue_props,) = resources.values()
    assert queue_props["Properties"]["VisibilityTimeout"] >= cdk.Duration.minutes(5).to_seconds()


def test_explicit_visibility_timeout_override_is_respected():
    stack = _test_stack()
    fn = _lambda.Function(
        stack,
        "SlowConsumer",
        runtime=_lambda.Runtime.PYTHON_3_12,
        handler="handler.main",
        code=_lambda.Code.from_inline("def main(event, context): pass"),
        timeout=cdk.Duration.minutes(5),
    )
    QueueWithDlq(
        stack,
        "StoryClusters",
        queue_name="story-clusters",
        consumer=fn,
        visibility_timeout=cdk.Duration.minutes(45),
    )

    template = Template.from_stack(stack)
    resources = template.find_resources("AWS::SQS::Queue", {
        "Properties": {"QueueName": "story-clusters"}
    })
    (queue_props,) = resources.values()
    assert queue_props["Properties"]["VisibilityTimeout"] == cdk.Duration.minutes(45).to_seconds()


def test_visibility_timeout_default_without_consumer_stays_60_seconds():
    stack = _test_stack()
    QueueWithDlq(stack, "NoConsumer", queue_name="no-consumer-queue")

    template = Template.from_stack(stack)
    resources = template.find_resources("AWS::SQS::Queue", {
        "Properties": {"QueueName": "no-consumer-queue"}
    })
    (queue_props,) = resources.values()
    assert queue_props["Properties"]["VisibilityTimeout"] == 60
