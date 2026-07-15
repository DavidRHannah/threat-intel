from aws_cdk import BundlingOptions, CustomResource, Duration
from aws_cdk import aws_lambda as _lambda
from aws_cdk import custom_resources as cr
from constructs import Construct

# The handler imports `neo4j`, which is not part of the Lambda runtime — it must be vendored
# into the deployment asset. `Code.from_asset(".")` alone only zips source, not dependencies;
# without bundling, the deployed Lambda fails at invoke time with
# `ModuleNotFoundError: No module named 'neo4j'` even though `cdk synth` and unit tests pass
# (per CLAUDE.md: a claim that code works requires it to actually run). Bundling requires
# Docker running locally (same Docker daemon already used for Task 2's Compose stack).
#
# Only `src/` is copied into the asset — the handler's import path (`src.common.
# schema_bootstrap_handler`) is a package under `src/`, and nothing else in the repo root is
# needed at runtime. Copying the whole repo (`cp -au .`) previously pulled in `.venv` (~576M),
# blowing past Lambda's 250MB unzipped limit and risking a locally gitignored `.env` (secrets)
# being staged into the deployment artifact — see NFR-SEC-01 (SSM SecureString only).
_BUNDLING = BundlingOptions(
    image=_lambda.Runtime.PYTHON_3_12.bundling_image,
    command=[
        "bash",
        "-c",
        "pip install neo4j==6.2.0 -t /asset-output && cp -au src /asset-output",
    ],
)


class SchemaBootstrapJob(Construct):
    def __init__(self, scope: Construct, construct_id: str, *, env_name: str) -> None:
        super().__init__(scope, construct_id)

        self.function = _lambda.Function(
            self,
            "Function",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="src.common.schema_bootstrap_handler.handler",
            code=_lambda.Code.from_asset(
                ".",
                bundling=_BUNDLING,
                exclude=[
                    ".venv",
                    ".git",
                    ".pytest_cache",
                    ".superpowers",
                    "crossroads.egg-info",
                    "tests",
                    "plans",
                    "progress-reports",
                    "*-layer",
                    "*.md",
                ],
            ),
            timeout=Duration.minutes(5),
            environment={"CROSSROADS_ENV": env_name},
        )
        provider = cr.Provider(self, "Provider", on_event_handler=self.function)
        CustomResource(self, "Resource", service_token=provider.service_token)
