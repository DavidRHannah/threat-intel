import aws_cdk as cdk
from aws_cdk.assertions import Match, Template

from infra.stacks.foundation_stack import FoundationStack


def test_stack_synthesizes_with_correct_env_name():
    app = cdk.App()
    stack = FoundationStack(app, "TestStack", env_name="dev")
    assert stack.env_name == "dev"


def test_creates_all_eight_dynamodb_tables():
    app = cdk.App()
    stack = FoundationStack(app, "TestStack", env_name="dev")
    template = Template.from_stack(stack)

    template.resource_count_is("AWS::DynamoDB::Table", 8)
    assert set(stack.tables.keys()) == {
        "Sources",
        "PollingState",
        "DedupState",
        "RECache",
        "Watchlists",
        "AlertState",
        "BriefingArchive",
        "ReconciliationReviewQueue",
    }


def test_dedup_state_table_has_composite_key():
    app = cdk.App()
    stack = FoundationStack(app, "TestStack", env_name="dev")
    template = Template.from_stack(stack)

    template.has_resource_properties(
        "AWS::DynamoDB::Table",
        {
            "TableName": "crossroads-dev-dedupstate",
            "KeySchema": Match.array_with(
                [
                    Match.object_like({"AttributeName": "source_id", "KeyType": "HASH"}),
                    Match.object_like({"AttributeName": "guid", "KeyType": "RANGE"}),
                ]
            ),
        },
    )


def test_creates_graph_writes_topic_and_schema_bootstrap_job():
    app = cdk.App()
    stack = FoundationStack(app, "TestStack", env_name="dev")
    template = Template.from_stack(stack)

    template.has_resource_properties("AWS::SNS::Topic", {"TopicName": "graph-writes"})
    template.resource_count_is("AWS::CloudFormation::CustomResource", 1)
