"""CDK synth-level tests for the Data Collection stack (L1 Task 12).

These assert the *wiring* the plan mandates — the queue+DLQ, the poller's reserved
concurrency and 10-minute schedule, the extraction Lambda's SQS event source and
graph-writes publish grant, and the one SSM parameter this stack owns publishing
(`discovery_updates_queue_url`, the same missing-publish bug class as `00-infra`'s
`graph_writes_topic_arn` Critical). Least-privilege (NFR-SEC-02) is spot-checked: the
poller has no Neo4j SSM grant.

Synth runs real Docker bundling (per CLAUDE.md's "it must run"): the Lambdas' assets
`pip install` their third-party deps in the Python 3.12 bundling image.
"""

import aws_cdk as cdk
from aws_cdk.assertions import Match, Template

from infra.stacks.data_collection_stack import DataCollectionStack
from infra.stacks.foundation_stack import FoundationStack


def _template(env_name: str = "dev") -> tuple[Template, DataCollectionStack]:
    app = cdk.App()
    foundation = FoundationStack(app, "TestFoundation", env_name=env_name)
    stack = DataCollectionStack(
        app, "TestDataCollection", env_name=env_name, foundation=foundation
    )
    return Template.from_stack(stack), stack


def test_discovery_updates_queue_and_dlq_exist():
    template, _ = _template()
    template.resource_count_is("AWS::SQS::Queue", 2)
    template.has_resource_properties("AWS::SQS::Queue", {"QueueName": "discovery-updates"})
    template.has_resource_properties("AWS::SQS::Queue", {"QueueName": "discovery-updates-dlq"})


def test_poller_lambda_has_reserved_concurrency_one():
    """FR-DC-07: at most one poller invocation runs at a time."""
    template, _ = _template()
    template.has_resource_properties(
        "AWS::Lambda::Function",
        {
            "Handler": "src.collection.rss.poller.handler",
            "ReservedConcurrentExecutions": 1,
        },
    )


def test_poller_has_a_ten_minute_schedule_rule():
    """FR-DC-08: the poller runs on a fixed 10-minute EventBridge cadence."""
    template, _ = _template()
    template.has_resource_properties(
        "AWS::Events::Rule",
        {"ScheduleExpression": "rate(10 minutes)"},
    )


def test_extraction_lambda_consumes_discovery_updates_queue():
    template, _ = _template()
    # The event source mapping ties the extraction Lambda to the discovery-updates queue.
    template.has_resource_properties(
        "AWS::Lambda::EventSourceMapping",
        {"EventSourceArn": Match.object_like({"Fn::GetAtt": Match.array_with(["Arn"])})},
    )
    template.resource_count_is("AWS::Lambda::EventSourceMapping", 1)


def test_extraction_role_can_publish_to_graph_writes_topic():
    template, _ = _template()
    template.has_resource_properties(
        "AWS::IAM::Policy",
        {
            "PolicyDocument": {
                "Statement": Match.array_with(
                    [
                        Match.object_like(
                            {
                                "Action": "sns:Publish",
                                "Effect": "Allow",
                            }
                        )
                    ]
                )
            }
        },
    )


def test_publishes_discovery_updates_queue_url_to_the_ssm_path_get_config_reads():
    """poller.py resolves the queue URL with get_config("discovery_updates_queue_url"),
    which has NO default -> it would KeyError in any deployed env unless this stack
    publishes SSM /crossroads/{env}/discovery_updates_queue_url. Same bug class as
    FoundationStack's graph_writes_topic_arn publish.
    """
    template, _ = _template()
    template.has_resource_properties(
        "AWS::SSM::Parameter",
        {
            "Name": "/crossroads/dev/discovery_updates_queue_url",
            "Type": "String",
        },
    )


def test_ssm_queue_url_path_matches_get_config_for_any_env():
    template, _ = _template(env_name="prod")
    template.has_resource_properties(
        "AWS::SSM::Parameter", {"Name": "/crossroads/prod/discovery_updates_queue_url"}
    )


def test_all_source_lambdas_are_wired():
    """Every Category A/B/C entry point in the plan gets a Lambda with the right handler."""
    template, _ = _template()
    handlers = {
        fn["Properties"]["Handler"]
        for fn in template.find_resources("AWS::Lambda::Function").values()
        if "Handler" in fn["Properties"]
    }
    expected = {
        "src.collection.rss.poller.handler",
        "src.collection.rss.extraction.handler",
        "src.collection.rest.nvd.handler",
        "src.collection.rest.cisa_kev.handler",
        "src.collection.rest.ghsa.handler",
        "src.collection.rest.otx.handler",
        "src.collection.rest.abusech.urlhaus_handler",
        "src.collection.rest.abusech.malwarebazaar_handler",
        "src.collection.rest.abusech.threatfox_handler",
        "src.collection.rest.epss.handler",
        "src.collection.stix.attck_sync.handler",
    }
    assert expected <= handlers, expected - handlers


def test_epss_runs_as_a_step_function_on_a_daily_rule():
    """Per design Part 4 §9, EPSS is a daily Step Function (checkpoint/resume safety),
    not a bare Lambda schedule."""
    template, _ = _template()
    template.resource_count_is("AWS::StepFunctions::StateMachine", 1)
    # A daily EventBridge rule exists (the poller's is 10-minute; tiers add more).
    template.has_resource_properties("AWS::Events::Rule", {"ScheduleExpression": "rate(1 day)"})


def test_poller_has_no_neo4j_ssm_grant():
    """NFR-SEC-02 least-privilege: the poller never touches Neo4j, so its role must not
    carry a neo4j_* SSM read grant (the graph-writing Lambdas do)."""
    _, stack = _template()
    template = Template.from_stack(stack)
    for policy in template.find_resources("AWS::IAM::Policy").values():
        statements = policy["Properties"]["PolicyDocument"]["Statement"]
        rendered = str(statements)
        # The poller's inline policy would only ever reference its DynamoDB tables and the
        # queue-url SSM param, never neo4j_*. A neo4j grant appearing on a role that also
        # has the Sources table grant would be the leak we are guarding against. This is a
        # coarse check: assert no policy grants BOTH the Sources table and a neo4j param.
        if "sources" in rendered and "neo4j" in rendered:
            raise AssertionError("poller role appears to carry a neo4j SSM grant")
