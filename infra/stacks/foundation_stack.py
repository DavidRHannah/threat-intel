from aws_cdk import RemovalPolicy, Stack
from aws_cdk import aws_dynamodb as dynamodb
from constructs import Construct

from infra.constructs.graph_writes_topic import GraphWritesTopic
from infra.constructs.iam_helpers import grant_ssm_read
from infra.constructs.schema_bootstrap_job import SchemaBootstrapJob

_TABLE_SPECS: dict[str, dict[str, str]] = {
    "Sources": {"partition_key": "source_id"},
    "PollingState": {"partition_key": "source_id"},
    "DedupState": {"partition_key": "source_id", "sort_key": "guid"},
    "RECache": {"partition_key": "re_target_content_hash"},
    "Watchlists": {"partition_key": "subscriber_id", "sort_key": "watchlist_id"},
    "AlertState": {"partition_key": "subscriber_id", "sort_key": "entity_event_type"},
    "BriefingArchive": {"partition_key": "briefing_id"},
    "ReconciliationReviewQueue": {
        "partition_key": "provisional_merge_key",
        "sort_key": "candidate_merge_key",
    },
}


class FoundationStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, *, env_name: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.env_name = env_name

        self.tables: dict[str, dynamodb.Table] = {}
        for name, spec in _TABLE_SPECS.items():
            table_kwargs = {
                "table_name": f"crossroads-{env_name}-{name.lower()}",
                "partition_key": dynamodb.Attribute(
                    name=spec["partition_key"], type=dynamodb.AttributeType.STRING
                ),
                "billing_mode": dynamodb.BillingMode.PAY_PER_REQUEST,
                "removal_policy": (
                    RemovalPolicy.RETAIN if env_name == "prod" else RemovalPolicy.DESTROY
                ),
            }
            if "sort_key" in spec:
                table_kwargs["sort_key"] = dynamodb.Attribute(
                    name=spec["sort_key"], type=dynamodb.AttributeType.STRING
                )
            self.tables[name] = dynamodb.Table(self, name, **table_kwargs)

        self.graph_writes_topic = GraphWritesTopic(self, "GraphWritesTopic")

        self.schema_bootstrap = SchemaBootstrapJob(self, "SchemaBootstrap", env_name=env_name)
        grant_ssm_read(
            self,
            self.schema_bootstrap.function.role,
            env_name=env_name,
            param_names=["neo4j_uri", "neo4j_user", "neo4j_password"],
        )
