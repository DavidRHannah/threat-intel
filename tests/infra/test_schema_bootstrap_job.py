import aws_cdk as cdk
from aws_cdk import Stack
from aws_cdk.assertions import Match, Template

from infra.constructs.schema_bootstrap_job import SchemaBootstrapJob


def test_creates_lambda_and_custom_resource():
    app = cdk.App()
    stack = Stack(app, "TestStack")

    job = SchemaBootstrapJob(stack, "SchemaBootstrap", env_name="dev")

    template = Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::Lambda::Function",
        {
            "Handler": "src.common.schema_bootstrap_handler.handler",
            "Runtime": "python3.12",
            "Environment": Match.object_like(
                {"Variables": Match.object_like({"CROSSROADS_ENV": "dev"})}
            ),
        },
    )
    template.resource_count_is("AWS::CloudFormation::CustomResource", 1)
    assert job.function is not None
