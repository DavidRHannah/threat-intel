import aws_cdk as cdk
from aws_cdk.assertions import Template

from infra.stacks.delivery_stack import DeliveryStack
from infra.stacks.foundation_stack import FoundationStack
from infra.stacks.interop_stack import InteropStack


def _synth_stack() -> tuple[DeliveryStack, Template]:
    app = cdk.App()
    foundation = FoundationStack(app, "CrossroadsFoundation-test", env_name="dev")
    interop = InteropStack(
        app, "CrossroadsInterop-test", env_name="dev", foundation=foundation,
    )
    stack = DeliveryStack(
        app, "CrossroadsDelivery-test", env_name="dev", foundation=foundation, interop=interop,
    )
    return stack, Template.from_stack(stack)


def _actions_granted_to(stack: DeliveryStack, template: Template, role) -> set[str]:
    """Per-role action set, not stack-wide (CLAUDE.md process lesson)."""
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


def test_synthesizes_fifteen_lambdas():
    _, template = _synth_stack()
    template.resource_count_is("AWS::Lambda::Function", 15)


def test_api_gateway_has_jwt_authorizer():
    _, template = _synth_stack()
    template.has_resource_properties(
        "AWS::ApiGatewayV2::Authorizer", {"AuthorizerType": "JWT"}
    )


def test_api_has_cors_configured_for_frontend_origin():
    _, template = _synth_stack()
    template.has_resource_properties(
        "AWS::ApiGatewayV2::Api",
        {"CorsConfiguration": {"AllowOrigins": ["http://localhost:5173"]}},
    )


def test_reuses_interop_user_pool_not_a_new_one():
    stack, template = _synth_stack()
    # Only InteropStack's TaxiiUserPool should exist -- DeliveryStack must not define its own
    # AWS::Cognito::UserPool resource (it adds a client + domain onto the shared pool).
    assert len(template.find_resources("AWS::Cognito::UserPool")) == 0


def test_each_dashboard_lambda_has_its_own_ssm_grant():
    stack, template = _synth_stack()
    for fn in [
        stack.stats_fn, stack.top_cves_fn, stack.top_actors_fn, stack.top_malware_fn,
        stack.recent_stories_fn, stack.subgraph_fn, stack.ttp_heatmap_fn, stack.search_fn,
    ]:
        actions = _actions_granted_to(stack, template, fn.role)
        assert "ssm:GetParameter" in actions


def test_each_asset_lambda_has_its_own_ssm_grant():
    stack, template = _synth_stack()
    for fn in [
        stack.create_asset_fn, stack.list_assets_fn, stack.delete_asset_fn,
        stack.asset_cves_fn, stack.all_assets_cves_fn, stack.known_vendor_products_fn,
    ]:
        actions = _actions_granted_to(stack, template, fn.role)
        assert "ssm:GetParameter" in actions


def test_api_cors_allows_post_and_delete():
    _, template = _synth_stack()
    template.has_resource_properties(
        "AWS::ApiGatewayV2::Api",
        {"CorsConfiguration": {"AllowMethods": ["GET", "POST", "DELETE"]}},
    )


def test_create_asset_route_exists():
    _, template = _synth_stack()
    template.has_resource_properties(
        "AWS::ApiGatewayV2::Route", {"RouteKey": "POST /assets"}
    )


def test_list_assets_route_exists():
    _, template = _synth_stack()
    template.has_resource_properties(
        "AWS::ApiGatewayV2::Route", {"RouteKey": "GET /assets"}
    )


def test_delete_asset_route_exists():
    _, template = _synth_stack()
    template.has_resource_properties(
        "AWS::ApiGatewayV2::Route", {"RouteKey": "DELETE /assets/{id}"}
    )


def test_asset_cves_route_exists():
    _, template = _synth_stack()
    template.has_resource_properties(
        "AWS::ApiGatewayV2::Route", {"RouteKey": "GET /assets/{id}/cves"}
    )


def test_all_assets_cves_route_exists():
    _, template = _synth_stack()
    template.has_resource_properties(
        "AWS::ApiGatewayV2::Route", {"RouteKey": "GET /assets/cves"}
    )


def test_known_vendor_products_route_exists():
    _, template = _synth_stack()
    template.has_resource_properties(
        "AWS::ApiGatewayV2::Route", {"RouteKey": "GET /assets/known-vendor-products"}
    )
