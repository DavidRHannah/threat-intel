"""CDK synth tests for AssetsStack.

Synth runs real Docker bundling (CLAUDE.md's "it must run"). NOTE: as of 2026-08-15
`tests/infra/` cannot actually run in this dev environment due to the documented
Python/jsii/Node bridge hang (see CLAUDE.md Current State) -- this file is written to the
same convention as `test_scoring_stack.py` and is ready to run once that is resolved.
"""

import aws_cdk as cdk
from aws_cdk.assertions import Template

from infra.stacks.assets_stack import AssetsStack
from infra.stacks.data_collection_stack import DataCollectionStack
from infra.stacks.foundation_stack import FoundationStack
from src.common.graph.publish import MESSAGE_TYPE_NODE_WRITE


def _synth(env_name: str = "dev") -> tuple[AssetsStack, Template]:
    app = cdk.App()
    foundation = FoundationStack(app, "TestFoundation", env_name=env_name)
    data_collection = DataCollectionStack(
        app, "TestDataCollection", env_name=env_name, foundation=foundation
    )
    stack = AssetsStack(
        app, "TestAssets", env_name=env_name,
        foundation=foundation, data_collection=data_collection,
    )
    return stack, Template.from_stack(stack)


def _template(env_name: str = "dev") -> Template:
    return _synth(env_name)[1]


def _actions_granted_to(stack: AssetsStack, template: Template, role) -> set[str]:
    """Every IAM action granted to exactly this role.

    Per-role, NOT stack-wide: a stack-wide action set says nothing about WHICH principal
    holds the grant, so it stays green when one of two Lambdas loses a grant the other
    still has. Mirrors test_scoring_stack.py's `_actions_granted_to`."""
    role_id = stack.get_logical_id(role.node.default_child)
    actions: set[str] = set()

    for policy in template.find_resources("AWS::IAM::Policy").values():
        refs = {
            r.get("Ref")
            for r in policy["Properties"].get("Roles", [])
            if isinstance(r, dict)
        }
        if role_id not in refs:
            continue
        for statement in policy["Properties"]["PolicyDocument"]["Statement"]:
            action = statement["Action"]
            actions.update(action if isinstance(action, list) else [action])
    return actions


def _properties_of(stack: AssetsStack, template: Template, fn) -> dict:
    logical_id = stack.get_logical_id(fn.node.default_child)
    return template.find_resources("AWS::Lambda::Function")[logical_id]["Properties"]


def test_synthesizes_two_lambdas():
    _template().resource_count_is("AWS::Lambda::Function", 2)


def test_sweep_has_daily_schedule():
    _template().has_resource_properties(
        "AWS::Events::Rule", {"ScheduleExpression": "rate(1 day)"}
    )


def test_event_lambda_subscription_filters_on_node_write_only():
    """Without this, the assets event Lambda is invoked on every article/edge write
    forever. Asserted against the publisher's own constant, matching L4's own
    subscription test, not two independent string literals."""
    _template().has_resource_properties(
        "AWS::SNS::Subscription",
        {"FilterPolicy": {"message_type": [MESSAGE_TYPE_NODE_WRITE]}},
    )


def test_each_lambda_runs_its_own_handler_entrypoint():
    """Both Lambdas share one asset, so both entrypoints exist in both bundles and a swap
    deploys cleanly without either raising on the other's payload shape."""
    stack, template = _synth()
    for fn, entrypoint in (
        (stack.event_fn, "src.assets.event_handler.handler"),
        (stack.sweep_fn, "src.assets.sweep_handler.handler"),
    ):
        assert _properties_of(stack, template, fn)["Handler"] == entrypoint


def test_both_lambdas_get_neo4j_ssm_read():
    """Both event_fn and sweep_fn call get_driver(), so BOTH need the SSM read.
    Asserted per Lambda, not stack-wide, per this repo's process lesson: a stack-wide
    action set stays green when one of two Lambdas loses its grant."""
    stack, template = _synth()
    for fn in (stack.event_fn, stack.sweep_fn):
        actions = _actions_granted_to(stack, template, fn.role)
        assert "ssm:GetParameter" in actions, f"{fn.node.id} has no Neo4j SSM read grant"


def test_event_lambda_is_not_over_granted_sns_publish():
    """Assets consumes graph-writes; it never publishes to it -- an AFFECTS edge write is
    not itself re-announced on the topic in this build."""
    stack, template = _synth()
    actions = _actions_granted_to(stack, template, stack.event_fn.role)
    assert not any(a.startswith("sns:Publish") for a in actions), (
        "event_fn is over-granted sns:Publish"
    )
