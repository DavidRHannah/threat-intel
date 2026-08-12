from aws_cdk import CfnOutput, RemovalPolicy, Stack
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_ssm as ssm
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
    "RevokedStixIds": {"partition_key": "stix_id"},
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

        # L3's runtime code resolves the topic ARN with `get_config("graph_writes_topic_arn")`,
        # which reads SSM `/crossroads/{env}/graph_writes_topic_arn` (src/common/config.py).
        # Nothing published that parameter, so the call raised KeyError in any deployed env.
        # This stack owns the topic, so this stack owns publishing its ARN. Keep this name and
        # `get_config`'s path convention in lockstep — the test asserts the exact path.
        #
        # A plaintext StringParameter, deliberately: an ARN is not a secret. NFR-SEC-01 scopes
        # SecureString to secrets, and a SecureString here would only add a KMS decrypt grant to
        # every subscriber for no confidentiality gain.
        self.graph_writes_topic_arn_param = ssm.StringParameter(
            self,
            "GraphWritesTopicArnParam",
            parameter_name=f"/crossroads/{env_name}/graph_writes_topic_arn",
            string_value=self.graph_writes_topic.topic.topic_arn,
        )

        # Cross-stack consumption path for L1-L7, per plans/00-infra.md Task 11's Interfaces.
        # Layer stacks in the same account/region should prefer CDK object refs where they can;
        # these exports exist for stacks (and operators) that resolve by name instead.
        CfnOutput(
            self,
            "GraphWritesTopicArn",
            value=self.graph_writes_topic.topic.topic_arn,
            export_name=f"{construct_id}:GraphWritesTopicArn",
        )
        for name, table in self.tables.items():
            CfnOutput(
                self,
                f"{name}TableName",
                value=table.table_name,
                export_name=f"{construct_id}:{name}TableName",
            )

        self.schema_bootstrap = SchemaBootstrapJob(self, "SchemaBootstrap", env_name=env_name)
        grant_ssm_read(
            self,
            self.schema_bootstrap.function.role,
            env_name=env_name,
            param_names=["neo4j_uri", "neo4j_user", "neo4j_password"],
        )
