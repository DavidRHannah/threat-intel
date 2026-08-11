"""CDK `DataCollectionStack` — wires L1's collection Lambdas, the discovery-updates
queue, the EPSS Step Function, and their EventBridge schedules onto the shared
`FoundationStack` substrate (Task 12).

Design decisions worth not re-deriving:

- **Shared substrate, not owned.** This stack takes the deployed `FoundationStack`'s
  `tables` dict and `graph_writes_topic` as constructor arguments; it never creates its
  own tables or topic. It owns the `discovery-updates` queue+DLQ, the Lambdas, the EPSS
  state machine, the schedule rules, and exactly one SSM parameter.
- **The one SSM parameter.** `poller.py` resolves the queue URL via
  `get_config("discovery_updates_queue_url")` with **no default** — it would `KeyError`
  in any deployed env. This stack publishes `/crossroads/{env}/discovery_updates_queue_url`
  (same missing-publish bug class as `00-infra`'s `graph_writes_topic_arn` Critical) and
  grants the poller SSM read on it.
- **The topic ARN travels as an env var**, not another SSM read: the topic is a direct
  CDK object ref here, so `CROSSROADS_GRAPH_WRITES_TOPIC_ARN` on the publishing Lambdas
  lets `get_config` resolve it with zero IAM surface (env vars beat SSM in `get_config`).
- **Neo4j credentials are SSM SecureString secrets** (`get_driver` reads
  `neo4j_uri`/`neo4j_user`/`neo4j_password`), so every graph-writing Lambda gets an SSM
  read grant for those three and `CROSSROADS_ENV` set so `get_config` resolves SSM rather
  than the local-dev defaults.
- **EventBridge tiering** (`data-collection-layer/design.md` Part 4 §10): one rule per
  tier, the tier's Lambdas as targets. Fast/15-min = URLhaus, MalwareBazaar, ThreatFox;
  Standard/hourly = NVD, GHSA, OTX; Slow/daily = CISA KEV. Plus EPSS (daily, Step
  Function) and ATT&CK (daily, Lambda).
- **Bundling follows `schema_bootstrap_job.py`'s pattern exactly.** `exclude` does NOT
  filter the bundling input — only the asset hash — so the `cp -au src` in the command is
  the only thing keeping `.venv`/`.env` out of the artifact. Each Lambda vendors only the
  third-party packages it imports; Lambdas sharing a dep set share one bundled asset.
"""

from pathlib import Path

from aws_cdk import BundlingOptions, Duration, Stack
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_ssm as ssm
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as sfn_tasks
from constructs import Construct

from infra.constructs.iam_helpers import (
    grant_dynamodb_read_write,
    grant_sns_publish,
    grant_ssm_read,
)
from infra.constructs.queue_with_dlq import QueueWithDlq
from infra.stacks.foundation_stack import FoundationStack

# infra/stacks/data_collection_stack.py -> parents[2] == repo root. Resolve from this
# module, never the process CWD (see schema_bootstrap_job.py's note).
_REPO_ROOT = str(Path(__file__).resolve().parents[2])

# Paths whose churn must NOT invalidate an asset hash — same list as schema_bootstrap_job.
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


def _bundled_code(pip_deps: tuple[str, ...]) -> _lambda.Code:
    """A `Code.from_asset` bundling `pip_deps` into the artifact alongside `src/`.

    `boto3` is in the Lambda runtime and is never vendored. Deps are sorted so two
    Lambdas requesting the same set produce an identical command → identical asset hash →
    a single shared bundle (CDK deduplicates)."""
    install = " ".join(sorted(pip_deps))
    return _lambda.Code.from_asset(
        _REPO_ROOT,
        bundling=BundlingOptions(
            image=_lambda.Runtime.PYTHON_3_12.bundling_image,
            command=[
                "bash",
                "-c",
                f"pip install {install} -t /asset-output && cp -au src /asset-output",
            ],
        ),
        exclude=_ASSET_EXCLUDE,
    )


class DataCollectionStack(Stack):
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
        self.env_name = env_name
        self._foundation = foundation
        self._topic_arn = foundation.graph_writes_topic.topic.topic_arn

        sources = foundation.tables["Sources"]
        polling = foundation.tables["PollingState"]
        dedup = foundation.tables["DedupState"]

        # --- Category A: Extraction Lambda + discovery-updates queue -----------------
        # The extraction Lambda MERGEs Articles (Neo4j) and publishes node-shaped
        # graph-writes announcements, so it needs the Neo4j secrets and sns:Publish.
        extraction_fn = _lambda.Function(
            self,
            "ExtractionFunction",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="src.collection.rss.extraction.handler",
            code=_bundled_code(("trafilatura==2.0.0", "neo4j==6.2.0")),
            timeout=Duration.minutes(2),
            memory_size=512,
            environment={
                "CROSSROADS_ENV": env_name,
                "CROSSROADS_GRAPH_WRITES_TOPIC_ARN": self._topic_arn,
            },
        )
        self._grant_graph_write(extraction_fn, publishes=True)

        self.discovery_updates = QueueWithDlq(
            self,
            "DiscoveryUpdates",
            queue_name="discovery-updates",
            consumer=extraction_fn,
        )

        # poller.py has no default for this key -> publish it (this stack owns the queue).
        # A plaintext String: a queue URL is not a secret (cf. FoundationStack's ARN param).
        self.queue_url_param = ssm.StringParameter(
            self,
            "DiscoveryUpdatesQueueUrlParam",
            parameter_name=f"/crossroads/{env_name}/discovery_updates_queue_url",
            string_value=self.discovery_updates.queue.queue_url,
        )

        # --- Category A: Poller Lambda (reserved concurrency 1, 10-min schedule) ------
        poller_fn = _lambda.Function(
            self,
            "PollerFunction",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="src.collection.rss.poller.handler",
            code=_bundled_code(("feedparser==6.0.11", "httpx==0.28.1")),
            timeout=Duration.minutes(5),
            memory_size=256,
            # FR-DC-07: at most one poller invocation at a time.
            reserved_concurrent_executions=1,
            environment={
                "CROSSROADS_ENV": env_name,
                "SOURCES_TABLE_NAME": sources.table_name,
                "DEDUP_STATE_TABLE_NAME": dedup.table_name,
                "POLLING_STATE_TABLE_NAME": polling.table_name,
            },
        )
        grant_dynamodb_read_write(poller_fn.role, sources)
        grant_dynamodb_read_write(poller_fn.role, dedup)
        grant_dynamodb_read_write(poller_fn.role, polling)
        # The poller resolves the queue URL from SSM (no Neo4j, no other secrets).
        grant_ssm_read(
            self,
            poller_fn.role,
            env_name=env_name,
            param_names=["discovery_updates_queue_url"],
        )
        # It also needs to send to the queue it publishes discovery/update events onto.
        self.discovery_updates.queue.grant_send_messages(poller_fn.role)

        self._schedule("PollerSchedule", Duration.minutes(10), [poller_fn])

        # --- Category B: REST source Lambdas, tiered ---------------------------------
        rest_deps = ("httpx==0.28.1", "neo4j==6.2.0")

        nvd_fn = self._rest_lambda(
            "NvdFunction", "src.collection.rest.nvd.handler", rest_deps, publishes=True
        )
        # NVD reads/writes PollingState (last_success_at window); no credential (keyless).
        grant_dynamodb_read_write(nvd_fn.role, polling)
        nvd_fn.add_environment("POLLING_STATE_TABLE_NAME", polling.table_name)

        ghsa_fn = self._rest_lambda(
            "GhsaFunction", "src.collection.rest.ghsa.handler", rest_deps, publishes=True
        )
        # GHSA needs a GitHub token (load_credential("ghsa", "token") -> ghsa_token).
        grant_ssm_read(self, ghsa_fn.role, env_name=env_name, param_names=["ghsa_token"])

        otx_fn = self._rest_lambda(
            "OtxFunction", "src.collection.rest.otx.handler", rest_deps, publishes=True
        )
        # OTX needs an API key (load_credential("otx", "api_key") -> otx_api_key).
        grant_ssm_read(self, otx_fn.role, env_name=env_name, param_names=["otx_api_key"])

        cisa_fn = self._rest_lambda(
            "CisaKevFunction", "src.collection.rest.cisa_kev.handler", rest_deps,
            publishes=True,
        )  # CISA KEV needs no credential (spec §6).

        urlhaus_fn = self._rest_lambda(
            "UrlhausFunction", "src.collection.rest.abusech.urlhaus_handler", rest_deps
        )
        grant_ssm_read(
            self, urlhaus_fn.role, env_name=env_name, param_names=["urlhaus_api_key"]
        )

        malwarebazaar_fn = self._rest_lambda(
            "MalwareBazaarFunction",
            "src.collection.rest.abusech.malwarebazaar_handler",
            rest_deps,
        )
        grant_ssm_read(
            self,
            malwarebazaar_fn.role,
            env_name=env_name,
            param_names=["malwarebazaar_api_key"],
        )

        threatfox_fn = self._rest_lambda(
            "ThreatFoxFunction",
            "src.collection.rest.abusech.threatfox_handler",
            rest_deps,
            publishes=True,
        )
        grant_ssm_read(
            self, threatfox_fn.role, env_name=env_name, param_names=["threatfox_api_key"]
        )

        # Tiers (design Part 4 §10): one rule per tier, its Lambdas as targets.
        self._schedule("FastTier", Duration.minutes(15), [urlhaus_fn, malwarebazaar_fn, threatfox_fn])
        self._schedule("StandardTier", Duration.hours(1), [nvd_fn, ghsa_fn, otx_fn])
        self._schedule("SlowTier", Duration.days(1), [cisa_fn])

        # --- Category B: EPSS daily Step Function ------------------------------------
        epss_fn = self._rest_lambda(
            "EpssFunction", "src.collection.rest.epss.handler", rest_deps
        )  # enrichment-only; no credential, no PollingState.
        epss_state_machine = sfn.StateMachine(
            self,
            "EpssStateMachine",
            definition_body=sfn.DefinitionBody.from_chainable(
                sfn_tasks.LambdaInvoke(self, "EpssRefresh", lambda_function=epss_fn)
            ),
            timeout=Duration.minutes(15),
        )
        events.Rule(
            self,
            "EpssSchedule",
            schedule=events.Schedule.rate(Duration.days(1)),
            targets=[targets.SfnStateMachine(epss_state_machine)],
        )

        # --- Category C: ATT&CK daily sync Lambda ------------------------------------
        attck_fn = self._graph_lambda(
            "AttckSyncFunction",
            "src.collection.stix.attck_sync.handler",
            ("stix2==3.0.1", "httpx==0.28.1", "neo4j==6.2.0"),
            timeout=Duration.minutes(10),
            memory_size=1024,
        )
        # ATT&CK persists last_ingested_versions in PollingState.
        grant_dynamodb_read_write(attck_fn.role, polling)
        attck_fn.add_environment("POLLING_STATE_TABLE_NAME", polling.table_name)
        self._schedule("AttckSchedule", Duration.days(1), [attck_fn])

    # --- helpers -------------------------------------------------------------------

    def _grant_graph_write(self, fn: _lambda.Function, *, publishes: bool) -> None:
        """Grant a graph-writing Lambda its Neo4j SSM secrets and (if it announces on the
        graph-writes topic) sns:Publish."""
        grant_ssm_read(self, fn.role, env_name=self.env_name, param_names=_NEO4J_SSM_PARAMS)
        if publishes:
            grant_sns_publish(fn.role, self._foundation.graph_writes_topic.topic)

    def _graph_lambda(
        self,
        construct_id: str,
        handler: str,
        pip_deps: tuple[str, ...],
        *,
        publishes: bool = False,
        timeout: Duration = Duration.minutes(5),
        memory_size: int = 512,
    ) -> _lambda.Function:
        environment = {"CROSSROADS_ENV": self.env_name}
        if publishes:
            environment["CROSSROADS_GRAPH_WRITES_TOPIC_ARN"] = self._topic_arn
        fn = _lambda.Function(
            self,
            construct_id,
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler=handler,
            code=_bundled_code(pip_deps),
            timeout=timeout,
            memory_size=memory_size,
            environment=environment,
        )
        self._grant_graph_write(fn, publishes=publishes)
        return fn

    def _rest_lambda(
        self,
        construct_id: str,
        handler: str,
        pip_deps: tuple[str, ...],
        *,
        publishes: bool = False,
    ) -> _lambda.Function:
        return self._graph_lambda(construct_id, handler, pip_deps, publishes=publishes)

    def _schedule(
        self, construct_id: str, rate: Duration, lambdas: list[_lambda.Function]
    ) -> events.Rule:
        return events.Rule(
            self,
            construct_id,
            schedule=events.Schedule.rate(rate),
            targets=[targets.LambdaFunction(fn) for fn in lambdas],
        )
