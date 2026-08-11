#!/usr/bin/env python3
import aws_cdk as cdk

from infra.stacks.data_collection_stack import DataCollectionStack
from infra.stacks.foundation_stack import FoundationStack
from infra.stacks.nlp_stack import NlpStack
from infra.stacks.scoring_stack import ScoringStack

app = cdk.App()
env_name = app.node.try_get_context("env") or "dev"
foundation = FoundationStack(app, f"CrossroadsFoundation-{env_name}", env_name=env_name)
DataCollectionStack(
    app,
    f"CrossroadsDataCollection-{env_name}",
    env_name=env_name,
    foundation=foundation,
)
NlpStack(
    app,
    f"CrossroadsNlp-{env_name}",
    env_name=env_name,
    foundation=foundation,
)
ScoringStack(
    app,
    f"CrossroadsScoring-{env_name}",
    env_name=env_name,
    foundation=foundation,
)
app.synth()
