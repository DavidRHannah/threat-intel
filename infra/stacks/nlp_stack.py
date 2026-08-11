"""CDK `NlpStack` — wires L2's four NLP Lambdas (Extraction, Resolution, Dedup,
Inference) and their three inter-stage queues onto the shared `FoundationStack`
substrate (`plans/02-nlp.md` Step 5.1).

Design decisions worth not re-deriving:

- **Shared substrate, not owned**, same as `DataCollectionStack`: this stack takes the
  deployed `FoundationStack`'s `tables` dict and `graph_writes_topic` as constructor
  arguments; it never creates its own tables or topic. It owns the three
  raw-mentions/resolved-articles/story-clusters queues+DLQs and the four Lambdas.
- **Extraction is not an SQS consumer.** Per `src/nlp/extraction/handler.py`'s module
  docstring, it subscribes directly to `graph-writes` SNS (L1's Extraction Lambda
  publishes a node-shaped `{node_label: "Article", ...}` announcement there after every
  Article MERGE) and sends its output to the `raw-mentions` SQS queue. Resolution,
  Dedup, and Inference are each the `consumer=` on their respective input queue.
- **Plan/reality gap — only ONE SNS subscription, not two.** `plans/02-nlp.md`'s Step
  5.1 text describes a second "reconciliation Lambda" also subscribed to `graph-writes`.
  `src/nlp/resolution/reconciliation.py` has a `reconcile()` function (its own docstring
  says the SNS wiring "is Phase 5's job") but no `handler()` wrapping it exists anywhere
  in this codebase, and nothing calls `reconcile()` outside its own module and tests. Per
  this task's explicit instruction, no placeholder Lambda is invented here to hit the
  plan's forward-looking subscription count — only Extraction's real subscription is
  wired. `ReconciliationReviewQueue`'s DynamoDB grant is still placed on Resolution (see
  below), since that's the package `reconcile()` lives in and the table this task's brief
  explicitly calls for; it is unused by any code path today.
- **Plan/reality gap — Extraction gets NO Neo4j grant and NO `sns:Publish` grant.**
  FR-EX-12 requires Extraction to never import or call `neo4j`/`get_driver`/
  `src.common.graph` (enforced by a real subprocess-import test in
  `tests/nlp/extraction/test_handler.py`), and `src/nlp/extraction/handler.py` only ever
  sends to the `raw-mentions` SQS queue — it never calls `publish_graph_write`. Granting
  either would violate NFR-SEC-02 least-privilege for a grant nothing in the code path
  could ever use.
- **Plan/reality gap — Resolution DOES need `anthropic_api_key`.**
  `src/nlp/resolution/handler.py`'s `_get_llm_client` calls
  `get_config("anthropic_api_key")` for fuzzy (LLM-assisted) resolution
  (`src/nlp/resolution/fuzzy.py`), contradicting the plan text's "resolution and dedup do
  not call an LLM" — Dedup alone calls no LLM.
- **Neo4j credentials are SSM SecureString secrets**, same pattern as
  `data_collection_stack.py`: every Lambda that calls `get_driver()` (Resolution, Dedup,
  Inference — not Extraction) gets an SSM read grant for `neo4j_uri`/`neo4j_user`/
  `neo4j_password` plus `CROSSROADS_ENV` so `get_config` resolves SSM rather than the
  local-dev defaults.
- **Queue URLs and table names travel as env vars, not SSM params.** Every producer
  Lambda and its downstream queue/table live in this same stack, so (mirroring
  `data_collection_stack.py`'s `CROSSROADS_GRAPH_WRITES_TOPIC_ARN` reasoning for a direct
  CDK object ref) there is no cross-stack resolution need that would justify the extra
  SSM `StringParameter` indirection `discovery_updates_queue_url` needed.
- **Bundling follows `data_collection_stack.py`/`schema_bootstrap_job.py`'s pattern
  exactly.** `exclude` does NOT filter the bundling input — only the asset hash — so the
  `cp -au src` in the command is the only thing keeping `.venv`/`.env` out of the
  artifact.
"""

from pathlib import Path

from aws_cdk import BundlingOptions, Duration, Stack
from aws_cdk import aws_lambda as _lambda
from constructs import Construct

from infra.constructs.iam_helpers import (
    grant_dynamodb_read_write,
    grant_sns_publish,
    grant_ssm_read,
)
from infra.constructs.queue_with_dlq import QueueWithDlq
from infra.stacks.foundation_stack import FoundationStack

# infra/stacks/nlp_stack.py -> parents[2] == repo root. Resolve from this module,
# never the process CWD (see schema_bootstrap_job.py's note).
_REPO_ROOT = str(Path(__file__).resolve().parents[2])

# Paths whose churn must NOT invalidate an asset hash — same list as
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

_ANTHROPIC_VERSION = "anthropic==0.68.0"
_NEO4J_VERSION = "neo4j==6.2.0"


def _bundled_code(pip_deps: tuple[str, ...]) -> _lambda.Code:
    """A `Code.from_asset` bundling `pip_deps` into the artifact alongside `src/`.

    `boto3` is in the Lambda runtime and is never vendored. Deps are sorted so two
    Lambdas requesting the same set produce an identical command -> identical asset
    hash -> a single shared bundle (CDK deduplicates)."""
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


class NlpStack(Stack):
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

        re_cache_table = foundation.tables["RECache"]
        reconciliation_review_table = foundation.tables["ReconciliationReviewQueue"]

        # --- Dedup: no LLM, no DynamoDB, no graph-writes publish -----------------------
        # Consumes `resolved-articles`, produces to `story-clusters`. Neo4j only (writes
        # story_cluster_id / reads/writes cluster state).
        self.dedup_fn = _lambda.Function(
            self,
            "DedupFunction",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="src.nlp.dedup.handler.handler",
            code=_bundled_code((_NEO4J_VERSION,)),
            timeout=Duration.minutes(2),
            memory_size=512,
            environment={"CROSSROADS_ENV": env_name},
        )
        grant_ssm_read(
            self, self.dedup_fn.role, env_name=env_name, param_names=_NEO4J_SSM_PARAMS
        )

        # --- Inference: LLM (relation extraction) + RECache + graph-writes publish -----
        # Consumes `story-clusters`; writes assertion edges via L3's
        # upsert_inferred_assertion and publishes a graph-writes notification per write.
        self.inference_fn = _lambda.Function(
            self,
            "InferenceFunction",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="src.nlp.inference.handler.handler",
            code=_bundled_code((_ANTHROPIC_VERSION, _NEO4J_VERSION)),
            timeout=Duration.minutes(5),
            memory_size=512,
            environment={
                "CROSSROADS_ENV": env_name,
                "CROSSROADS_GRAPH_WRITES_TOPIC_ARN": self._topic_arn,
                "CROSSROADS_RE_CACHE_TABLE_NAME": re_cache_table.table_name,
            },
        )
        grant_ssm_read(
            self,
            self.inference_fn.role,
            env_name=env_name,
            param_names=[*_NEO4J_SSM_PARAMS, "anthropic_api_key"],
        )
        grant_dynamodb_read_write(self.inference_fn.role, re_cache_table)
        grant_sns_publish(self.inference_fn.role, foundation.graph_writes_topic.topic)

        # --- Resolution: LLM (fuzzy resolution) + ReconciliationReviewQueue + publish --
        # Consumes `raw-mentions`; writes MENTIONS edges via L3's write_mentions_edge and
        # publishes a graph-writes notification per resolved mention.
        self.resolution_fn = _lambda.Function(
            self,
            "ResolutionFunction",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="src.nlp.resolution.handler.handler",
            code=_bundled_code((_ANTHROPIC_VERSION, _NEO4J_VERSION)),
            timeout=Duration.minutes(2),
            memory_size=512,
            environment={
                "CROSSROADS_ENV": env_name,
                "CROSSROADS_GRAPH_WRITES_TOPIC_ARN": self._topic_arn,
                "CROSSROADS_RECONCILIATION_REVIEW_QUEUE_TABLE_NAME": (
                    reconciliation_review_table.table_name
                ),
            },
        )
        grant_ssm_read(
            self,
            self.resolution_fn.role,
            env_name=env_name,
            param_names=[*_NEO4J_SSM_PARAMS, "anthropic_api_key"],
        )
        grant_dynamodb_read_write(self.resolution_fn.role, reconciliation_review_table)
        grant_sns_publish(self.resolution_fn.role, foundation.graph_writes_topic.topic)

        # --- Extraction: LLM only. NO Neo4j (FR-EX-12), NO sns:Publish -----------------
        # Not an SQS consumer -- subscribed directly to graph-writes SNS. Sends its
        # output to `raw-mentions`.
        self.extraction_fn = _lambda.Function(
            self,
            "ExtractionFunction",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="src.nlp.extraction.handler.handler",
            code=_bundled_code((_ANTHROPIC_VERSION,)),
            timeout=Duration.minutes(2),
            memory_size=512,
            environment={"CROSSROADS_ENV": env_name},
        )
        grant_ssm_read(
            self,
            self.extraction_fn.role,
            env_name=env_name,
            param_names=["anthropic_api_key"],
        )
        foundation.graph_writes_topic.subscribe_lambda(
            self.extraction_fn, message_types=["article"]
        )

        # --- Queues: created consumer-first so each producer can be granted send access
        # and given the downstream queue URL once it exists. -----------------------------
        self.story_clusters_queue = QueueWithDlq(
            self, "StoryClusters", queue_name="story-clusters", consumer=self.inference_fn
        )
        self.dedup_fn.add_environment(
            "CROSSROADS_STORY_CLUSTERS_QUEUE_URL", self.story_clusters_queue.queue.queue_url
        )
        self.story_clusters_queue.queue.grant_send_messages(self.dedup_fn.role)

        self.resolved_articles_queue = QueueWithDlq(
            self,
            "ResolvedArticles",
            queue_name="resolved-articles",
            consumer=self.dedup_fn,
        )
        self.resolution_fn.add_environment(
            "CROSSROADS_RESOLVED_ARTICLES_QUEUE_URL",
            self.resolved_articles_queue.queue.queue_url,
        )
        self.resolved_articles_queue.queue.grant_send_messages(self.resolution_fn.role)

        self.raw_mentions_queue = QueueWithDlq(
            self, "RawMentions", queue_name="raw-mentions", consumer=self.resolution_fn
        )
        self.extraction_fn.add_environment(
            "CROSSROADS_RAW_MENTIONS_QUEUE_URL", self.raw_mentions_queue.queue.queue_url
        )
        self.raw_mentions_queue.queue.grant_send_messages(self.extraction_fn.role)
