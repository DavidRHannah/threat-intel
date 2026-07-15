import aws_cdk as cdk
from aws_cdk.assertions import Template

from infra.stacks.foundation_stack import FoundationStack


def test_stack_synthesizes_with_correct_env_name():
    app = cdk.App()
    stack = FoundationStack(app, "TestStack", env_name="dev")
    template = Template.from_stack(stack)

    assert stack.env_name == "dev"
    template.resource_count_is("AWS::CloudFormation::Stack", 0)
