import aws_cdk as cdk
from aws_cdk import Stack, aws_dynamodb as dynamodb, aws_iam as iam, aws_sns as sns
from aws_cdk.assertions import Match, Template

from infra.constructs.iam_helpers import (
    grant_dynamodb_read_write,
    grant_sns_publish,
    grant_ssm_read,
)


def _test_stack() -> Stack:
    app = cdk.App(context={"@aws-cdk/core:target-partitions": ["aws"]})
    return Stack(app, "TestStack", env=cdk.Environment(account="111111111111", region="us-east-1"))


def test_grant_ssm_read_scopes_to_named_parameters():
    stack = _test_stack()
    role = iam.Role(stack, "Role", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))

    grant_ssm_read(stack, role, env_name="dev", param_names=["neo4j_uri", "neo4j_password"])

    template = Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::IAM::Policy",
        {
            "PolicyDocument": Match.object_like(
                {
                    "Statement": Match.array_with(
                        [
                            Match.object_like(
                                {
                                    "Action": "ssm:GetParameter",
                                    "Resource": Match.array_with(
                                        [
                                            Match.string_like_regexp(
                                                r".*parameter/crossroads/dev/neo4j_uri$"
                                            ),
                                            Match.string_like_regexp(
                                                r".*parameter/crossroads/dev/neo4j_password$"
                                            ),
                                        ]
                                    ),
                                }
                            )
                        ]
                    )
                }
            )
        },
    )


def test_grant_dynamodb_read_write_grants_table_access():
    stack = _test_stack()
    role = iam.Role(stack, "Role", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
    table = dynamodb.Table(
        stack,
        "Table",
        partition_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING),
    )

    grant_dynamodb_read_write(role, table)

    template = Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::IAM::Policy",
        {
            "PolicyDocument": Match.object_like(
                {
                    "Statement": Match.array_with(
                        [Match.object_like({"Action": Match.array_with(["dynamodb:GetItem"])})]
                    )
                }
            )
        },
    )


def test_grant_sns_publish_grants_topic_publish():
    stack = _test_stack()
    role = iam.Role(stack, "Role", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
    topic = sns.Topic(stack, "Topic", topic_name="graph-writes")

    grant_sns_publish(role, topic)

    template = Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::IAM::Policy",
        {
            "PolicyDocument": Match.object_like(
                {
                    "Statement": Match.array_with(
                        [Match.object_like({"Action": "sns:Publish"})]
                    )
                }
            )
        },
    )
