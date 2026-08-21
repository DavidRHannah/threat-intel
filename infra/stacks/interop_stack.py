"""L5 Interoperability: TAXII 2.1 API + the graph-writes watermark consumer.

Bundling/environment conventions mirror infra/stacks/scoring_stack.py -- read that file
first if any of `_bundled_code`/`_ASSET_EXCLUDE` looks unfamiliar.
"""

from pathlib import Path

import yaml
from aws_cdk import BundlingOptions, Duration, Stack
from aws_cdk import aws_apigatewayv2 as apigwv2
from aws_cdk import aws_apigatewayv2_authorizers as authorizers
from aws_cdk import aws_apigatewayv2_integrations as integrations
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_lambda as _lambda
from constructs import Construct

from infra.constructs.iam_helpers import grant_dynamodb_read_write, grant_ssm_read
from infra.stacks.foundation_stack import FoundationStack

_REPO_ROOT = str(Path(__file__).resolve().parents[2])
_INTEROP_YAML = str(Path(_REPO_ROOT) / "config" / "interop.yaml")

_ASSET_EXCLUDE = [
    ".venv", ".git", ".claude", ".pytest_cache", ".superpowers", "**/__pycache__",
    "crossroads.egg-info", "tests", "plans", "progress-reports", "*-layer", "*.md",
]

_NEO4J_SSM_PARAMS = ["neo4j_credentials"]
_NEO4J_VERSION = "neo4j==6.2.0"
_STIX2_VERSION = "stix2==3.0.1"

_REQUIRED_KNOBS = (
    "export_confidence_floor", "stix_namespace", "collection_id", "collection_title",
    "sweep_batch_size",
)


def _knob_env() -> dict[str, str]:
    with open(_INTEROP_YAML) as fh:
        knobs = yaml.safe_load(fh) or {}
    missing = [k for k in _REQUIRED_KNOBS if k not in knobs]
    if missing:
        raise ValueError(f"missing required interop knob(s) in {_INTEROP_YAML}: {missing}")
    return {f"CROSSROADS_{k.upper()}": str(knobs[k]) for k in _REQUIRED_KNOBS}


def _bundled_code() -> _lambda.Code:
    return _lambda.Code.from_asset(
        _REPO_ROOT,
        bundling=BundlingOptions(
            image=_lambda.Runtime.PYTHON_3_12.bundling_image,
            command=[
                "bash", "-c",
                f"pip install {_NEO4J_VERSION} {_STIX2_VERSION} -t /asset-output "
                "&& cp -au src /asset-output",
            ],
        ),
        exclude=_ASSET_EXCLUDE,
    )


class InteropStack(Stack):
    def __init__(
        self, scope: Construct, construct_id: str, *, env_name: str,
        foundation: FoundationStack, **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        env = {
            "CROSSROADS_ENV": env_name,
            **_knob_env(),
            "CROSSROADS_REVOKED_STIX_IDS_TABLE_NAME": (
                foundation.tables["RevokedStixIds"].table_name
            ),
        }
        code = _bundled_code()

        self.discovery_fn = _lambda.Function(
            self, "TaxiiDiscoveryFunction", runtime=_lambda.Runtime.PYTHON_3_12,
            handler="src.interop.taxii_handler.discovery_handler", code=code,
            timeout=Duration.seconds(10), memory_size=256, environment=env,
        )
        self.collections_fn = _lambda.Function(
            self, "TaxiiCollectionsFunction", runtime=_lambda.Runtime.PYTHON_3_12,
            handler="src.interop.taxii_handler.collections_handler", code=code,
            timeout=Duration.seconds(10), memory_size=256, environment=env,
        )
        self.objects_fn = _lambda.Function(
            self, "TaxiiObjectsFunction", runtime=_lambda.Runtime.PYTHON_3_12,
            handler="src.interop.taxii_handler.objects_handler", code=code,
            timeout=Duration.minutes(1), memory_size=512, environment=env,
        )
        for fn in (self.discovery_fn, self.collections_fn, self.objects_fn):
            grant_ssm_read(
                self, fn.role, env_name=env_name, param_names=_NEO4J_SSM_PARAMS
            )
        # objects_handler calls scan_revoked_tombstones() on EVERY request, which scans the
        # RevokedStixIds table. Without this grant the endpoint 500s on every call in any
        # deployed env (the KeyError-degradation path in queries.py only covers `local`).
        # A read-write grant, not read-only: this codebase keeps one DynamoDB helper and
        # does not maintain a separate read-only variant (infra/constructs/iam_helpers.py).
        grant_dynamodb_read_write(self.objects_fn.role, foundation.tables["RevokedStixIds"])

        # --- watermark_handler: graph-writes consumer -------------------------------
        self.watermark_fn = _lambda.Function(
            self, "InteropWatermarkFunction", runtime=_lambda.Runtime.PYTHON_3_12,
            handler="src.interop.watermark_handler.handler", code=code,
            timeout=Duration.minutes(2), memory_size=512, environment=env,
        )
        grant_ssm_read(
            self, self.watermark_fn.role, env_name=env_name, param_names=_NEO4J_SSM_PARAMS
        )
        grant_dynamodb_read_write(
            self.watermark_fn.role, foundation.tables["RevokedStixIds"]
        )
        # Unfiltered node/edge/article writes plus the reconciliation-merge signal
        # (Task 1.1's new message_type) -- every type this consumer knows how to stamp.
        foundation.graph_writes_topic.subscribe_lambda(
            self.watermark_fn,
            message_types=["edge_write", "node_write", "article", "node_merge"],
        )

        # --- API Gateway (HTTP API) + Cognito JWT authorizer ------------------------
        self.user_pool = cognito.UserPool(self, "TaxiiUserPool", self_sign_up_enabled=False)
        self.user_pool_client = self.user_pool.add_client("TaxiiClient")
        authorizer = authorizers.HttpJwtAuthorizer(
            "TaxiiAuthorizer",
            jwt_issuer=(
                f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool.user_pool_id}"
            ),
            jwt_audience=[self.user_pool_client.user_pool_client_id],
        )

        # NOTE: CDK's HttpApi.add_routes rejects a path ending in "/" (RoutePathAlwaysStart)
        # except for the bare root "/" -- the brief's TAXII-conventional trailing-slash paths
        # ("/taxii2/", ".../collections/", ".../objects/") don't synth under aws-cdk-lib
        # 2.260.0. Trailing slashes dropped here; no test in this task pins exact route paths.
        self.api = apigwv2.HttpApi(self, "TaxiiApi")
        self.api.add_routes(
            path="/taxii2",
            methods=[apigwv2.HttpMethod.GET],
            integration=integrations.HttpLambdaIntegration(
                "DiscoveryIntegration", self.discovery_fn,
            ),
            authorizer=authorizer,
        )
        self.api.add_routes(
            path="/taxii2/api/collections",
            methods=[apigwv2.HttpMethod.GET],
            integration=integrations.HttpLambdaIntegration(
                "CollectionsIntegration", self.collections_fn,
            ),
            authorizer=authorizer,
        )
        self.api.add_routes(
            path="/taxii2/api/collections/{collection_id}/objects",
            methods=[apigwv2.HttpMethod.GET],
            integration=integrations.HttpLambdaIntegration(
                "ObjectsIntegration", self.objects_fn,
            ),
            authorizer=authorizer,
        )
