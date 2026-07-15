#!/usr/bin/env python3
import aws_cdk as cdk

from infra.stacks.foundation_stack import FoundationStack

app = cdk.App()
env_name = app.node.try_get_context("env") or "dev"
FoundationStack(app, f"CrossroadsFoundation-{env_name}", env_name=env_name)
app.synth()
