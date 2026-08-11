"""L4 Scoring: the graph-writes event consumer plus the daily sweep state machine.

Reads `config/scoring.yaml` at SYNTH time and emits every knob as a CROSSROADS_* Lambda
environment variable, which src/common/config.py resolves ahead of SSM. Git stays the
single source of truth and `cdk diff` shows a knob change as an explicit template diff.
"""

from pathlib import Path

import yaml
from aws_cdk import BundlingOptions, Duration, Stack
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_lambda_destinations as destinations
from aws_cdk import aws_sqs as sqs
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as sfn_tasks
from constructs import Construct

from infra.constructs.iam_helpers import grant_ssm_read
from infra.stacks.foundation_stack import FoundationStack

# The handler's DECLARED phase order, imported rather than restated. It is LOAD-BEARING:
# `prune_flags` reads the confidence that `confidence_rescan` and `decay` repair, so a
# state machine built from a stale copy condemns entities on values the same sweep was
# about to fix -- and a phase added later (as `confidence_rescan` was, in Task 5.1) would
# silently never run in production. Precedent for importing src/ at synth time:
# infra/constructs/schema_bootstrap_job.py.
from src.scoring.sweep_handler import PHASES as _SWEEP_PHASES

# infra/stacks/scoring_stack.py -> parents[2] == repo root. Resolve from this module,
# never the process CWD (see schema_bootstrap_job.py's note).
_REPO_ROOT = str(Path(__file__).resolve().parents[2])
_SCORING_YAML = str(Path(_REPO_ROOT) / "config" / "scoring.yaml")

# Paths whose churn must NOT invalidate an asset hash -- same list as nlp_stack.py /
# data_collection_stack.py / schema_bootstrap_job.py.
_ASSET_EXCLUDE = [
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
]

_NEO4J_SSM_PARAMS = ["neo4j_uri", "neo4j_user", "neo4j_password"]
_NEO4J_VERSION = "neo4j==6.2.0"

# Mirrors src/scoring/knobs.py. Listed explicitly rather than accepting whatever the YAML
# happens to contain: a typo'd or deleted key must fail at synth, not silently fall back
# to a code default at runtime and score the whole graph with the wrong weight.
_REQUIRED_KNOBS = (
    "w_impact",
    "w_likelihood",
    "w_adoption",
    "adoption_saturation_k",
    "kev_floor",
    "band_critical",
    "band_high",
    "band_medium",
    "w_novelty",
    "w_credibility",
    "w_centrality",
    "novelty_halflife_days",
    "centrality_saturation_c",
    "decay_halflife_days",
    "prune_confidence_floor",
    "prune_stale_days",
    "edge_confidence_floor",
    "sweep_batch_size",
)

# The sweep phase list is deliberately NOT restated here -- it is imported as
# `_SWEEP_PHASES` from src.scoring.sweep_handler at the top of this module.


def _knob_env() -> dict[str, str]:
    with open(_SCORING_YAML) as fh:
        knobs = yaml.safe_load(fh) or {}
    missing = [k for k in _REQUIRED_KNOBS if k not in knobs]
    if missing:
        raise ValueError(f"missing required scoring knob(s) in {_SCORING_YAML}: {missing}")
    return {f"CROSSROADS_{k.upper()}": str(knobs[k]) for k in _REQUIRED_KNOBS}


def _bundled_code() -> _lambda.Code:
    """Both L4 Lambdas share one bundle: same deps, same `src/`, so CDK deduplicates the
    asset. `exclude` only filters the asset hash -- the `cp -au src` is what keeps
    `.venv`/`.env` out of the artifact."""
    return _lambda.Code.from_asset(
        _REPO_ROOT,
        bundling=BundlingOptions(
            image=_lambda.Runtime.PYTHON_3_12.bundling_image,
            command=[
                "bash",
                "-c",
                f"pip install {_NEO4J_VERSION} -t /asset-output && cp -au src /asset-output",
            ],
        ),
        exclude=_ASSET_EXCLUDE,
    )


def _state_id(prefix: str, phase: str) -> str:
    """`severity_rescan` -> `SweepSeverityRescan`. State ids only; the phase name itself
    travels to the handler verbatim in the task payload."""
    return prefix + phase.title().replace("_", "")


class ScoringStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        env_name: str,
        foundation: FoundationStack,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        env = {"CROSSROADS_ENV": env_name, **_knob_env()}
        code = _bundled_code()

        # SNS -> Lambda is an ASYNC invoke with no DLQ by default. Scores are derived, so
        # this DLQ is for observability: the daily sweep re-derives anything lost here.
        # It captures invocations that FAILED after SNS handed them to Lambda; an SNS-side
        # delivery failure before that is not covered (the subscription has no redrive
        # policy) and is likewise absorbed by the sweep.
        self.dlq = sqs.Queue(
            self,
            "ScoringEventDlq",
            queue_name=f"crossroads-{env_name}-scoring-event-dlq",
            retention_period=Duration.days(14),
        )

        self.event_fn = _lambda.Function(
            self,
            "ScoringEventFunction",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="src.scoring.event_handler.handler",
            code=code,
            timeout=Duration.minutes(2),
            memory_size=512,
            environment=env,
            on_failure=destinations.SqsDestination(self.dlq),
        )
        grant_ssm_read(
            self, self.event_fn.role, env_name=env_name, param_names=_NEO4J_SSM_PARAMS
        )
        # No sns:Publish grant: L4 consumes graph-writes and never publishes to it.
        foundation.graph_writes_topic.subscribe_lambda(
            self.event_fn, message_types=["edge_write", "node_write"]
        )

        self.sweep_fn = _lambda.Function(
            self,
            "ScoringSweepFunction",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="src.scoring.sweep_handler.handler",
            code=code,
            timeout=Duration.minutes(5),
            memory_size=1024,
            environment=env,
        )
        grant_ssm_read(
            self, self.sweep_fn.role, env_name=env_name, param_names=_NEO4J_SSM_PARAMS
        )

        self.state_machine = sfn.StateMachine(
            self,
            "ScoringSweepStateMachine",
            definition_body=sfn.DefinitionBody.from_chainable(self._sweep_definition()),
            timeout=Duration.hours(6),
        )
        events.Rule(
            self,
            "ScoringSweepSchedule",
            schedule=events.Schedule.rate(Duration.days(1)),
            targets=[targets.SfnStateMachine(self.state_machine)],
        )

    def _sweep_definition(self) -> sfn.IChainable:
        """One paginated loop per phase, chained. Each phase drives itself to `done:true`
        before the next begins, so a page is always small enough to finish inside the
        Lambda timeout no matter how large the graph grows."""
        chain: sfn.IChainable | None = None
        tail: sfn.Choice | None = None

        for phase in _SWEEP_PHASES:
            invoke = sfn_tasks.LambdaInvoke(
                self,
                _state_id("Sweep", phase),
                lambda_function=self.sweep_fn,
                payload=sfn.TaskInput.from_object(
                    {"phase": phase, "cursor": sfn.JsonPath.string_at("$.cursor")}
                ),
                result_selector={
                    # The handler returns "" (never null) when a scan is exhausted, so
                    # both of these stay type-stable across every iteration. `string_at`
                    # is the only `.$` accessor CDK exposes; ASL itself copies the value
                    # untyped, so `done` arrives as the boolean the handler returned.
                    "cursor": sfn.JsonPath.string_at("$.Payload.cursor"),
                    "done": sfn.JsonPath.string_at("$.Payload.done"),
                    # Carried so the execution history records how much work each page
                    # did. A sweep that hits the 6h cap half-done is otherwise invisible
                    # outside the Lambda's own logs.
                    "count": sfn.JsonPath.number_at("$.Payload.count"),
                },
            )
            # CDK already retries the four Lambda SERVICE exceptions. Neither of these is
            # covered by that, and both are expected rather than exotic on a daily job:
            # a throttle when the account is busy, and a transient Neo4j
            # ServiceUnavailable surfacing as a handler error. Without them one blip
            # aborts the whole sweep mid-phase and nothing downstream of it runs.
            invoke.add_retry(
                errors=["Lambda.TooManyRequestsException"],
                interval=Duration.seconds(5),
                max_attempts=6,
                backoff_rate=2,
            )
            invoke.add_retry(
                errors=["States.TaskFailed"],
                interval=Duration.seconds(10),
                max_attempts=3,
                backoff_rate=2,
            )
            done = sfn.Choice(self, _state_id("Done", phase))
            step = invoke.next(done)
            done.when(sfn.Condition.boolean_equals("$.done", False), invoke)

            # Empty string, NOT null: JsonPath.string_at on a JSON null fails the
            # execution at runtime. The handler treats "" as "no cursor".
            start = sfn.Pass(
                self, _state_id("Start", phase), parameters={"cursor": ""}
            ).next(step)

            if chain is None:
                chain = start
            else:
                tail.otherwise(start)
            tail = done

        if tail is None:
            raise ValueError("sweep PHASES is empty -- the daily sweep would do nothing")
        tail.otherwise(sfn.Succeed(self, "SweepComplete"))
        return chain
