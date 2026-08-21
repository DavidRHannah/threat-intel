"""L7 Delivery: the read API + auth slice (FR-DEL-01, FR-DEL-03, FR-DEL-09).

Bundling/environment conventions mirror infra/stacks/interop_stack.py. Auth reuses L5's
TaxiiUserPool (spec decision 1, 2026-08-13 design doc) rather than standing up a second
Cognito pool -- a new UserPoolClient + Hosted UI domain are added onto that shared pool so
dashboard tokens carry their own audience, distinct from TAXII's.
"""

from pathlib import Path

import yaml
from aws_cdk import BundlingOptions, CfnOutput, Duration, Stack
from aws_cdk import aws_apigatewayv2 as apigwv2
from aws_cdk import aws_apigatewayv2_authorizers as authorizers
from aws_cdk import aws_apigatewayv2_integrations as integrations
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_lambda as _lambda
from constructs import Construct

from infra.constructs.iam_helpers import grant_ssm_read
from infra.stacks.foundation_stack import FoundationStack
from infra.stacks.interop_stack import InteropStack

_REPO_ROOT = str(Path(__file__).resolve().parents[2])
_DELIVERY_YAML = str(Path(_REPO_ROOT) / "config" / "delivery.yaml")

_ASSET_EXCLUDE = [
    ".venv", ".git", ".claude", ".pytest_cache", ".superpowers", "**/__pycache__",
    "crossroads.egg-info", "tests", "plans", "progress-reports", "*-layer", "*.md",
]

_NEO4J_SSM_PARAMS = ["neo4j_credentials"]
_NEO4J_VERSION = "neo4j==6.2.0"

_REQUIRED_KNOBS = (
    "dashboard_default_limit", "search_result_limit", "ttp_heatmap_recency_halflife_days",
)

# Deterministic, synth-time-known Hosted UI domain prefix (must be a literal, not a CDK
# token -- self.account is unresolved at synth time). Suffixed with the deployed account's
# last 6 digits (248911656849, CLAUDE.md Current State) for practical global uniqueness.
_COGNITO_DOMAIN_PREFIX = "crossroads-dev-656849"

# Local Vite dev server -- the only frontend origin that exists today (no CloudFront/S3
# hosting stack yet, per CLAUDE.md's frontend Current State).
_FRONTEND_ORIGIN = "http://localhost:5173"


def _knob_env() -> dict[str, str]:
    with open(_DELIVERY_YAML) as fh:
        knobs = yaml.safe_load(fh) or {}
    missing = [k for k in _REQUIRED_KNOBS if k not in knobs]
    if missing:
        raise ValueError(f"missing required delivery knob(s) in {_DELIVERY_YAML}: {missing}")
    return {f"CROSSROADS_{k.upper()}": str(knobs[k]) for k in _REQUIRED_KNOBS}


def _bundled_code() -> _lambda.Code:
    return _lambda.Code.from_asset(
        _REPO_ROOT,
        bundling=BundlingOptions(
            image=_lambda.Runtime.PYTHON_3_12.bundling_image,
            command=[
                "bash", "-c",
                f"pip install {_NEO4J_VERSION} -t /asset-output && cp -au src /asset-output",
            ],
        ),
        exclude=_ASSET_EXCLUDE,
    )


class DeliveryStack(Stack):
    def __init__(
        self, scope: Construct, construct_id: str, *, env_name: str,
        foundation: FoundationStack, interop: InteropStack, **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        env = {"CROSSROADS_ENV": env_name, **_knob_env()}
        code = _bundled_code()

        # --- Auth: reuse InteropStack's TaxiiUserPool, add a dashboard-scoped client -----
        self.dashboard_client = interop.user_pool.add_client(
            "DashboardClient",
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(implicit_code_grant=True),
                scopes=[cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL],
                callback_urls=[f"{_FRONTEND_ORIGIN}/callback"],
                logout_urls=[f"{_FRONTEND_ORIGIN}/login"],
            ),
        )
        self.domain = interop.user_pool.add_domain(
            "DashboardDomain",
            cognito_domain=cognito.CognitoDomainOptions(domain_prefix=_COGNITO_DOMAIN_PREFIX),
        )
        authorizer = authorizers.HttpJwtAuthorizer(
            "DashboardAuthorizer",
            jwt_issuer=(
                f"https://cognito-idp.{self.region}.amazonaws.com/{interop.user_pool.user_pool_id}"
            ),
            jwt_audience=[self.dashboard_client.user_pool_client_id],
        )

        def _fn(name: str, handler: str) -> _lambda.Function:
            fn = _lambda.Function(
                self, name, runtime=_lambda.Runtime.PYTHON_3_12, handler=handler, code=code,
                timeout=Duration.seconds(30), memory_size=512, environment=env,
            )
            grant_ssm_read(self, fn.role, env_name=env_name, param_names=_NEO4J_SSM_PARAMS)
            return fn

        self.stats_fn = _fn("StatsFunction", "src.delivery.dashboard_handler.stats_handler")
        self.top_cves_fn = _fn(
            "TopCvesFunction", "src.delivery.dashboard_handler.top_cves_handler"
        )
        self.top_actors_fn = _fn(
            "TopActorsFunction", "src.delivery.dashboard_handler.top_actors_handler"
        )
        self.top_malware_fn = _fn(
            "TopMalwareFunction", "src.delivery.dashboard_handler.top_malware_handler"
        )
        self.top_campaigns_fn = _fn(
            "TopCampaignsFunction", "src.delivery.dashboard_handler.top_campaigns_handler"
        )
        self.recent_stories_fn = _fn(
            "RecentStoriesFunction", "src.delivery.dashboard_handler.recent_stories_handler"
        )
        self.subgraph_fn = _fn(
            "SubgraphFunction", "src.delivery.dashboard_handler.subgraph_handler"
        )
        self.ttp_heatmap_fn = _fn(
            "TtpHeatmapFunction", "src.delivery.ttp_heatmap_handler.handler"
        )
        self.search_fn = _fn("SearchFunction", "src.delivery.search_handler.handler")
        self.create_asset_fn = _fn(
            "CreateAssetFunction", "src.delivery.assets_handler.create_asset_handler"
        )
        self.list_assets_fn = _fn(
            "ListAssetsFunction", "src.delivery.assets_handler.list_assets_handler"
        )
        self.delete_asset_fn = _fn(
            "DeleteAssetFunction", "src.delivery.assets_handler.delete_asset_handler"
        )
        self.asset_cves_fn = _fn(
            "AssetCvesFunction", "src.delivery.assets_handler.asset_cves_handler"
        )
        self.all_assets_cves_fn = _fn(
            "AllAssetsCvesFunction", "src.delivery.assets_handler.all_assets_cves_handler"
        )
        self.known_vendor_products_fn = _fn(
            "KnownVendorProductsFunction",
            "src.delivery.assets_handler.known_vendor_products_handler",
        )

        # --- API Gateway (HTTP API), CORS for the browser-facing frontend ---------------
        self.api = apigwv2.HttpApi(
            self, "DeliveryApi",
            cors_preflight=apigwv2.CorsPreflightOptions(
                allow_origins=[_FRONTEND_ORIGIN],
                allow_methods=[
                    apigwv2.CorsHttpMethod.GET, apigwv2.CorsHttpMethod.POST,
                    apigwv2.CorsHttpMethod.DELETE,
                ],
                allow_headers=["Authorization", "Content-Type"],
            ),
        )

        CfnOutput(self, "DashboardClientId", value=self.dashboard_client.user_pool_client_id)
        CfnOutput(self, "CognitoDomain", value=self.domain.domain_name)
        CfnOutput(self, "DeliveryApiUrl", value=self.api.url)

        routes = [
            ("/dashboard/stats", "GET", self.stats_fn, "StatsIntegration"),
            ("/dashboard/top-cves", "GET", self.top_cves_fn, "TopCvesIntegration"),
            ("/dashboard/top-actors", "GET", self.top_actors_fn, "TopActorsIntegration"),
            ("/dashboard/top-malware", "GET", self.top_malware_fn, "TopMalwareIntegration"),
            (
                "/dashboard/top-campaigns", "GET", self.top_campaigns_fn,
                "TopCampaignsIntegration",
            ),
            (
                "/dashboard/recent-stories", "GET", self.recent_stories_fn,
                "RecentStoriesIntegration",
            ),
            ("/dashboard/subgraph/{id}", "GET", self.subgraph_fn, "SubgraphIntegration"),
            ("/dashboard/ttp-heatmap", "GET", self.ttp_heatmap_fn, "TtpHeatmapIntegration"),
            ("/search", "GET", self.search_fn, "SearchIntegration"),
            ("/assets", "POST", self.create_asset_fn, "CreateAssetIntegration"),
            ("/assets", "GET", self.list_assets_fn, "ListAssetsIntegration"),
            ("/assets/{id}", "DELETE", self.delete_asset_fn, "DeleteAssetIntegration"),
            ("/assets/{id}/cves", "GET", self.asset_cves_fn, "AssetCvesIntegration"),
            ("/assets/cves", "GET", self.all_assets_cves_fn, "AllAssetsCvesIntegration"),
            (
                "/assets/known-vendor-products", "GET", self.known_vendor_products_fn,
                "KnownVendorProductsIntegration",
            ),
        ]
        for path, method, fn, integration_id in routes:
            self.api.add_routes(
                path=path,
                methods=[apigwv2.HttpMethod[method]],
                integration=integrations.HttpLambdaIntegration(integration_id, fn),
                authorizer=authorizer,
            )
