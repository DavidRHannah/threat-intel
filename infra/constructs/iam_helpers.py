from aws_cdk import Stack
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_sns as sns
from constructs import Construct


def grant_ssm_read(
    scope: Construct, role: iam.IRole, *, env_name: str, param_names: list[str]
) -> None:
    # Wildcard-scoped to the env path rather than the individual param_names: get_config()
    # calls with a Python-level default (e.g. rss_poll_timeout_seconds) still hit SSM first
    # in a non-local env, and AccessDeniedException isn't caught the way ParameterNotFound
    # is -- so any config knob missing from an exact per-name grant hard-fails at runtime
    # instead of falling back to its default. param_names is kept as a required, documented
    # argument (what this role is known to read) even though it no longer narrows the grant.
    del param_names
    stack = Stack.of(scope)
    resource = f"arn:aws:ssm:{stack.region}:{stack.account}:parameter/crossroads/{env_name}/*"
    role.add_to_principal_policy(
        iam.PolicyStatement(actions=["ssm:GetParameter"], resources=[resource])
    )


def grant_dynamodb_read_write(role: iam.IRole, table: dynamodb.ITable) -> None:
    table.grant_read_write_data(role)


def grant_sns_publish(role: iam.IRole, topic: sns.ITopic) -> None:
    topic.grant_publish(role)
