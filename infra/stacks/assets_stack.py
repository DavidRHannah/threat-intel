"""Assets: event-driven + daily-sweep AFFECTS-edge matcher (design spec §5, §7, Decision 8).
Asset CRUD/read API lives in DeliveryStack instead -- this stack owns only the backend
graph-processing Lambdas, which should not ride Delivery's deploy cadence.
"""

from pathlib import Path

from aws_cdk import BundlingOptions, Duration, Stack
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_lambda as _lambda
from constructs import Construct

from infra.constructs.iam_helpers import grant_ssm_read
from infra.stacks.data_collection_stack import DataCollectionStack
from infra.stacks.foundation_stack import FoundationStack

_REPO_ROOT = str(Path(__file__).resolve().parents[2])
_ASSET_EXCLUDE = [
    ".venv", ".git", ".claude", ".pytest_cache", ".superpowers", "**/__pycache__",
    "crossroads.egg-info", "tests", "plans", "progress-reports", "*-layer", "*.md",
]
_NEO4J_SSM_PARAMS = ["neo4j_uri", "neo4j_user", "neo4j_password"]
_NEO4J_VERSION = "neo4j==6.2.0"


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


class AssetsStack(Stack):
    def __init__(
        self, scope: Construct, construct_id: str, *, env_name: str,
        foundation: FoundationStack, data_collection: DataCollectionStack, **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # `data_collection` is accepted for interface parity with every other post-
        # DataCollection stack (Scoring, Interop) and because a future asset-matching
        # signal sourced from L1's own tables/queues is plausible -- it is NOT currently
        # referenced. The graph-writes topic this stack actually subscribes to lives on
        # `foundation` (`FoundationStack.graph_writes_topic`, a `GraphWritesTopic`
        # construct), not on `data_collection` -- confirmed by grepping
        # `infra/stacks/scoring_stack.py`, which subscribes via
        # `foundation.graph_writes_topic.subscribe_lambda(...)`, the existing filtered-
        # subscription pattern this stack mirrors. `data_collection_stack.py` only ever
        # reads `foundation.graph_writes_topic` too (to publish, not own it).
        del data_collection
        env = {"CROSSROADS_ENV": env_name}
        code = _bundled_code()

        self.event_fn = _lambda.Function(
            self, "AssetsEventFunction", runtime=_lambda.Runtime.PYTHON_3_12,
            handler="src.assets.event_handler.handler", code=code,
            timeout=Duration.seconds(30), memory_size=512, environment=env,
        )
        grant_ssm_read(self, self.event_fn.role, env_name=env_name, param_names=_NEO4J_SSM_PARAMS)

        # message_type filtering happens at the subscription (matches L4's
        # event_handler.py); the `CPEMatch`-vs-other node label filtering happens inside
        # the handler itself, per Task 7.
        foundation.graph_writes_topic.subscribe_lambda(
            self.event_fn, message_types=["node_write"]
        )

        self.sweep_fn = _lambda.Function(
            self, "AssetsSweepFunction", runtime=_lambda.Runtime.PYTHON_3_12,
            handler="src.assets.sweep_handler.handler", code=code,
            timeout=Duration.minutes(5), memory_size=512, environment=env,
        )
        grant_ssm_read(self, self.sweep_fn.role, env_name=env_name, param_names=_NEO4J_SSM_PARAMS)

        # Single daily invocation; the handler is one page per invocation (batch_size
        # knob, `assets_sweep_batch_size`, defaulted to 500 in
        # `src.assets.sweep_handler._batch_size` itself -- no CDK-baked knob env needed,
        # `get_config`'s own Python-level default covers it the same way
        # `rss_poll_timeout_seconds` does elsewhere), so full reconciliation across a
        # large asset set needs a loop -- deferred to a Step Function if/when asset counts
        # justify it (single-tenant scale today is small; a single Lambda invocation
        # processing every asset in one pass is enough for now, matching the spec's
        # "batch from the start, don't need a Step Function yet" call).
        rule = events.Rule(
            self, "AssetsDailySweepRule", schedule=events.Schedule.rate(Duration.days(1)),
        )
        rule.add_target(targets.LambdaFunction(self.sweep_fn))
