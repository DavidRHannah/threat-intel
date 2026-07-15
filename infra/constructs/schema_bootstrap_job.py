import hashlib
import json
from pathlib import Path

from aws_cdk import BundlingOptions, CustomResource, Duration
from aws_cdk import aws_lambda as _lambda
from aws_cdk import custom_resources as cr
from constructs import Construct

import src.common.schema_bootstrap as schema_bootstrap


def schema_version() -> str:
    """A content hash of every schema input `bootstrap_schema()` applies.

    This is the CustomResource's re-run trigger. CloudFormation only sends an `Update` event
    when a resource's *template properties* change; a Lambda code update is not a replacement
    and does not change `ServiceToken`. With `ServiceToken` as the only property, the handler
    would therefore run on **Create only** — adding a constraint to `UNIQUE_CONSTRAINTS` would
    rebuild the asset, update the function, report a successful deploy, and never invoke the
    handler. The constraint would silently not exist, surfacing later as a data-integrity bug
    rather than a deploy failure. Hashing the schema makes the property move whenever the
    schema does, which is what makes the "self-applies on every deploy" architecture in
    `plans/00-infra.md` actually true.

    Every input must be covered or a change to an uncovered one silently won't re-run — hence
    the vector-index config, not just the constraint list. Module attributes are read at call
    time (not import time) so the hash always reflects the live values.

    Known gap, deliberate: the vector dimension is resolved at *runtime* by
    `get_config("embedding_dimensions", default=DEFAULT_VECTOR_DIMENSIONS)`, so this hash can
    only cover the default. Editing the `embedding_dimensions` SSM parameter without a code
    change will not re-trigger the bootstrap; the index would need to be dropped and re-created
    deliberately anyway (Neo4j will not resize one in place), so that is a manual operation
    either way, not something a deploy should silently do.
    """
    payload = json.dumps(
        {
            "unique_constraints": [list(c) for c in schema_bootstrap.UNIQUE_CONSTRAINTS],
            "vector_index": {
                "name": "article_embedding_index",
                "label": "Article",
                "property": "embedding",
                "dimensions": schema_bootstrap.DEFAULT_VECTOR_DIMENSIONS,
                "similarity": schema_bootstrap.VECTOR_SIMILARITY,
            },
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()

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
#
# !! `exclude` does not filter the bundling input — only the hash. !!
# The `cp -au src` above is the ONLY thing keeping `.venv`/`.env` out of the artifact. CDK
# passes the whole asset directory into the bundling container regardless of `exclude`; the
# exclude list below feeds `FileSystem.fingerprint` (which paths changing should invalidate the
# asset hash) and nothing else. So reverting `cp -au src` back to `cp -au .` on the assumption
# that `exclude` protects the artifact would silently ship `.venv` and any local `.env`. It
# does not protect it. Change the `cp` line, not the exclude list, if the copied set must grow.
_BUNDLING = BundlingOptions(
    image=_lambda.Runtime.PYTHON_3_12.bundling_image,
    command=[
        "bash",
        "-c",
        "pip install neo4j==6.2.0 -t /asset-output && cp -au src /asset-output",
    ],
)

# Resolve the asset root from this module, never from the process CWD. `Code.from_asset(".")`
# resolves against wherever `cdk synth` / pytest happened to be invoked from, so synthesizing
# from any directory but the repo root silently produces a wrong asset.
# infra/constructs/schema_bootstrap_job.py -> parents[2] == repo root.
_REPO_ROOT = str(Path(__file__).resolve().parents[2])


class SchemaBootstrapJob(Construct):
    def __init__(self, scope: Construct, construct_id: str, *, env_name: str) -> None:
        super().__init__(scope, construct_id)

        self.function = _lambda.Function(
            self,
            "Function",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="src.common.schema_bootstrap_handler.handler",
            code=_lambda.Code.from_asset(
                _REPO_ROOT,
                bundling=_BUNDLING,
                # Purely a fingerprinting concern (see the note above _BUNDLING): these are the
                # paths whose churn must NOT invalidate the asset hash. `.claude` matters once
                # this branch merges — the repo root then holds `.claude/worktrees/*/.venv`
                # (~576M), and fingerprinting would walk that whole tree on every synth.
                exclude=[
                    ".venv",
                    ".git",
                    ".claude",
                    ".pytest_cache",
                    ".superpowers",
                    "**/__pycache__",
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
        CustomResource(
            self,
            "Resource",
            service_token=provider.service_token,
            properties={"SchemaVersion": schema_version()},
        )
