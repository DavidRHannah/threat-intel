from aws_cdk import Stack
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_sns as sns
from constructs import Construct


def grant_ssm_read(
    scope: Construct, role: iam.IRole, *, env_name: str, param_names: list[str]
) -> None:
    stack = Stack.of(scope)
    resources = [
        f"arn:aws:ssm:{stack.region}:{stack.account}:parameter/crossroads/{env_name}/{name}"
        for name in param_names
    ]
    role.add_to_principal_policy(
        iam.PolicyStatement(actions=["ssm:GetParameter"], resources=resources)
    )


def grant_dynamodb_read_write(role: iam.IRole, table: dynamodb.ITable) -> None:
    table.grant_read_write_data(role)


def grant_sns_publish(role: iam.IRole, topic: sns.ITopic) -> None:
    topic.grant_publish(role)
