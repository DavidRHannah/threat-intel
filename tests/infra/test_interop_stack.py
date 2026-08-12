import aws_cdk as cdk
from aws_cdk.assertions import Template

from infra.stacks.foundation_stack import FoundationStack
from infra.stacks.interop_stack import InteropStack


def _synth_stack() -> tuple[InteropStack, Template]:
    app = cdk.App()
    foundation = FoundationStack(app, "CrossroadsFoundation-test", env_name="dev")
    stack = InteropStack(
        app, "CrossroadsInterop-test", env_name="dev", foundation=foundation,
    )
    return stack, Template.from_stack(stack)


def _synth():
    _, template = _synth_stack()
    return template


def _actions_granted_to(stack: InteropStack, template: Template, role) -> set[str]:
    """Every IAM action granted to exactly this role.

    Per-role, NOT stack-wide: a stack-wide action set says nothing about WHICH principal
    holds the grant, so it stays green when the grant silently moves to (or leaks onto) a
    different Lambda's role. Mirrors tests/infra/test_scoring_stack.py's helper of the same
    name (per CLAUDE.md's "assertion over a STACK-WIDE set cannot pin a PER-PRINCIPAL fact"
    process lesson)."""
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


def test_synthesizes_four_lambdas():
    template = _synth()
    template.resource_count_is("AWS::Lambda::Function", 4)


def test_api_gateway_has_cognito_authorizer():
    template = _synth()
    template.has_resource_properties(
        "AWS::ApiGatewayV2::Authorizer", {"AuthorizerType": "JWT"}
    )


def test_watermark_fn_subscribed_to_graph_writes_topic():
    template = _synth()
    template.has_resource_properties(
        "AWS::SNS::Subscription",
        {
            "Protocol": "lambda",
            "FilterPolicy": {
                "message_type": ["edge_write", "node_write", "article", "node_merge"]
            },
        },
    )


def test_watermark_fn_has_dynamodb_grant_to_revoked_table():
    """Grants are PER-PRINCIPAL, not stack-wide -- resolve the watermark function's own
    role logical id and assert on ITS actions specifically (per CLAUDE.md's L4-build
    process lesson: "An assertion over a STACK-WIDE set cannot pin a PER-PRINCIPAL
    fact")."""
    stack, template = _synth_stack()
    actions = _actions_granted_to(stack, template, stack.watermark_fn.role)
    assert "dynamodb:PutItem" in actions, (
        f"watermark_fn's role has no dynamodb:PutItem grant; actions={actions}"
    )


def test_objects_fn_has_dynamodb_read_grant_to_revoked_table():
    """`objects_handler` scans RevokedStixIds on every request (`scan_revoked_tombstones`).
    Without a grant on ITS OWN role, every GET .../objects raises AccessDeniedException in
    any deployed env. Per-principal for the same reason as the watermark test above."""
    stack, template = _synth_stack()
    actions = _actions_granted_to(stack, template, stack.objects_fn.role)
    assert "dynamodb:Scan" in actions, (
        f"objects_fn's role has no dynamodb:Scan grant; actions={actions}"
    )
