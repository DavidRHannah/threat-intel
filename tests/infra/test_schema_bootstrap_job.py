import aws_cdk as cdk
import pytest
from aws_cdk import Stack
from aws_cdk.assertions import Match, Template

import src.common.schema_bootstrap as schema_bootstrap
from infra.constructs.schema_bootstrap_job import SchemaBootstrapJob, schema_version


def _custom_resource_properties(stack: Stack) -> dict:
    resources = Template.from_stack(stack).find_resources("AWS::CloudFormation::CustomResource")
    (resource,) = resources.values()
    return resource["Properties"]


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


def test_custom_resource_carries_a_schema_version_property():
    """Without a schema-derived property, ServiceToken is the CustomResource's only property.
    It resolves to the provider Lambda's ARN, which is stable across code changes, so
    CloudFormation never sends an Update event and bootstrap_schema() runs on Create only —
    a new constraint would silently never be applied. See plans/00-infra.md Task 10.
    """
    app = cdk.App()
    stack = Stack(app, "TestStack")
    SchemaBootstrapJob(stack, "SchemaBootstrap", env_name="dev")

    properties = _custom_resource_properties(stack)
    assert "SchemaVersion" in properties
    assert isinstance(properties["SchemaVersion"], str)
    assert properties["SchemaVersion"]


def test_schema_version_changes_when_the_constraint_list_changes(monkeypatch):
    """The whole point of the property: presence is not enough, it must actually track the
    schema. If this passes while the value is a constant, the re-run trigger is decorative.
    """
    before = schema_version()

    monkeypatch.setattr(
        schema_bootstrap,
        "UNIQUE_CONSTRAINTS",
        [*schema_bootstrap.UNIQUE_CONSTRAINTS, ("new_thing_unique", "NewThing", "new_key")],
    )

    assert schema_version() != before


@pytest.mark.parametrize(
    "attribute, value",
    [
        ("DEFAULT_VECTOR_DIMENSIONS", 512),
        ("VECTOR_SIMILARITY", "euclidean"),
    ],
)
def test_schema_version_covers_every_vector_index_input(monkeypatch, attribute, value):
    """The hash must cover *every* schema input bootstrap_schema() applies — a change to an
    uncovered input would silently not re-run.
    """
    before = schema_version()
    monkeypatch.setattr(schema_bootstrap, attribute, value)
    assert schema_version() != before


def test_schema_version_is_stable_across_calls():
    assert schema_version() == schema_version()
