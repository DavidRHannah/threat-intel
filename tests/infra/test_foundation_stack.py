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


def test_publishes_graph_writes_topic_arn_to_the_ssm_path_get_config_reads():
    """L3's runtime path resolves the topic ARN with get_config("graph_writes_topic_arn"),
    which reads SSM /crossroads/{env}/graph_writes_topic_arn. Nothing populated it, so that
    call would have raised KeyError in every deployed env. The parameter name here and
    src.common.config.get_config's convention must stay in lockstep.
    """
    app = cdk.App()
    stack = FoundationStack(app, "TestStack", env_name="dev")
    template = Template.from_stack(stack)

    template.has_resource_properties(
        "AWS::SSM::Parameter",
        {
            "Name": "/crossroads/dev/graph_writes_topic_arn",
            # Plaintext String, not SecureString: an ARN is not a secret, so NFR-SEC-01
            # (which scopes SecureString to secrets) does not apply.
            "Type": "String",
            "Value": {"Ref": Match.any_value()},
        },
    )


def test_ssm_parameter_path_matches_get_config_for_any_env():
    app = cdk.App()
    stack = FoundationStack(app, "TestStack", env_name="prod")
    Template.from_stack(stack).has_resource_properties(
        "AWS::SSM::Parameter", {"Name": "/crossroads/prod/graph_writes_topic_arn"}
    )


def test_exports_table_names_and_topic_arn_as_stack_outputs():
    app = cdk.App()
    stack = FoundationStack(app, "TestStack", env_name="dev")
    outputs = Template.from_stack(stack).find_outputs("*")

    assert "GraphWritesTopicArn" in outputs
    for name in stack.tables:
        assert f"{name}TableName" in outputs, f"no CfnOutput exporting the {name} table name"
    for output in outputs.values():
        assert output["Export"]["Name"].startswith("TestStack:"), output
