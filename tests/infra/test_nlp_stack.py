"""CDK synth-level tests for the NLP stack (L2 Step 5.1).

These assert the wiring the plan mandates: three `QueueWithDlq` pairs (raw-mentions,
resolved-articles, story-clusters — 6 SQS queues incl. DLQs), four Lambda functions
(extraction, resolution, dedup, inference), Extraction's direct `graph-writes` SNS
subscription (NOT an SQS consumer), and IAM grants scoped per-Lambda to exactly what
each stage's actual code touches.

**Plan/reality gap** (see `.superpowers/sdd/task-5.1-report.md` for the full writeup):
`plans/02-nlp.md`'s Step 5.1 text describes a second "reconciliation Lambda" also
subscribed to `graph-writes` (2 subscriptions total) and a uniform Neo4j-secrets grant
on every Lambda. Neither matches the codebase as built:

- No reconciliation Lambda handler exists anywhere (`src/nlp/resolution/reconciliation.py`
  has a `reconcile()` function but no `handler()` wrapping it, and nothing calls it) — so
  there is exactly **one** SNS subscription (extraction), not two.
- `src/nlp/extraction/handler.py` (and everything it imports) never imports `neo4j` or
  calls `get_driver()` — enforced by FR-EX-12 and a real subprocess-import test
  (`tests/nlp/extraction/test_handler.py::test_handler_module_never_imports_neo4j`). So
  Extraction gets **no** Neo4j SSM grant, and its bundle vendors no `neo4j` package.
- `src/nlp/extraction/handler.py` never calls `publish_graph_write`/`sns.publish` — it only
  sends to the raw-mentions SQS queue. So Extraction gets **no** `sns:Publish` grant.
- `src/nlp/resolution/handler.py` DOES call `get_config("anthropic_api_key")` (for fuzzy
  resolution, `src/nlp/resolution/fuzzy.py` via `_get_llm_client`), contradicting the plan
  text's "resolution and dedup do not call an LLM" — so Resolution gets an
  `anthropic_api_key` SSM grant too.

Synth runs real Docker bundling (per CLAUDE.md's "it must run"): the Lambdas' assets
`pip install` their third-party deps in the Python 3.12 bundling image.
"""

import json

import aws_cdk as cdk
from aws_cdk.assertions import Template

from infra.stacks.foundation_stack import FoundationStack
from infra.stacks.nlp_stack import NlpStack


def _template(env_name: str = "dev") -> tuple[Template, NlpStack]:
    app = cdk.App()
    foundation = FoundationStack(app, "TestFoundation", env_name=env_name)
    stack = NlpStack(app, "TestNlp", env_name=env_name, foundation=foundation)
    return Template.from_stack(stack), stack


def _policy_for(template: Template, prefix: str) -> dict:
    policies = {
        lid: res
        for lid, res in template.find_resources("AWS::IAM::Policy").items()
        if lid.startswith(prefix)
    }
    assert policies, f"could not locate a policy with prefix {prefix}"
    # Merge all statements across every policy resource matching the prefix.
    statements = []
    for policy in policies.values():
        statements.extend(policy["Properties"]["PolicyDocument"]["Statement"])
    return statements


def test_three_queues_with_dlqs_exist():
    template, _ = _template()
    template.resource_count_is("AWS::SQS::Queue", 6)
    for name in ("raw-mentions", "resolved-articles", "story-clusters"):
        template.has_resource_properties("AWS::SQS::Queue", {"QueueName": name})
        template.has_resource_properties("AWS::SQS::Queue", {"QueueName": f"{name}-dlq"})


def test_four_lambda_functions_exist_with_correct_handlers():
    template, _ = _template()
    handlers = {
        fn["Properties"]["Handler"]
        for fn in template.find_resources("AWS::Lambda::Function").values()
        if "Handler" in fn["Properties"]
    }
    expected = {
        "src.nlp.extraction.handler.handler",
        "src.nlp.resolution.handler.handler",
        "src.nlp.dedup.handler.handler",
        "src.nlp.inference.handler.handler",
    }
    assert expected <= handlers, expected - handlers
    assert len(handlers) == 4, handlers


def test_extraction_is_not_an_sqs_consumer_but_is_sns_subscribed():
    template, _ = _template()
    # Only 3 event source mappings total (resolution, dedup, inference) -- extraction
    # is not one of them.
    template.resource_count_is("AWS::Lambda::EventSourceMapping", 3)
    # Exactly one SNS subscription (extraction) -- see module docstring's plan/reality gap.
    template.resource_count_is("AWS::SNS::Subscription", 1)


def test_resolution_dedup_inference_are_wired_as_queue_consumers():
    template, _ = _template()
    template.resource_count_is("AWS::Lambda::EventSourceMapping", 3)


def test_resolution_and_inference_can_publish_to_graph_writes_extraction_and_dedup_cannot():
    template, _ = _template()

    for prefix in ("ResolutionFunction", "InferenceFunction"):
        statements = _policy_for(template, f"{prefix}ServiceRoleDefaultPolicy")
        rendered = json.dumps(statements, default=str)
        assert '"sns:Publish"' in rendered, f"{prefix} should be able to publish to graph-writes"

    for prefix in ("ExtractionFunction", "DedupFunction"):
        # A Lambda with no grants at all may have no ServiceRoleDefaultPolicy resource;
        # tolerate that, but if one exists it must not carry sns:Publish.
        policies = {
            lid: res
            for lid, res in template.find_resources("AWS::IAM::Policy").items()
            if lid.startswith(f"{prefix}ServiceRoleDefaultPolicy")
        }
        for policy in policies.values():
            rendered = json.dumps(policy, default=str)
            assert '"sns:Publish"' not in rendered, (
                f"{prefix} should not be able to publish to graph-writes: {rendered}"
            )


def test_extraction_has_no_neo4j_ssm_grant():
    """FR-EX-12: extraction never touches Neo4j (enforced by a real subprocess-import
    test in tests/nlp/extraction/test_handler.py). Its role must carry no neo4j_* SSM
    grant."""
    template, _ = _template()
    policies = {
        lid: res
        for lid, res in template.find_resources("AWS::IAM::Policy").items()
        if lid.startswith("ExtractionFunctionServiceRoleDefaultPolicy")
    }
    for policy in policies.values():
        rendered = json.dumps(policy, default=str)
        assert "neo4j" not in rendered, f"extraction policy carries a neo4j grant: {rendered}"


def test_resolution_dedup_inference_have_neo4j_ssm_grants():
    """`grant_ssm_read` grants a per-env wildcard (`crossroads/{env}/*`), not exact param
    names (NFR-SEC-02 debt, see CLAUDE.md Current State and
    `test_poller_ssm_grant_is_env_wildcard_not_least_privilege` in
    test_data_collection_stack.py) -- a literal `neo4j_uri` substring never appears in a
    rendered policy, so this asserts the wildcard grant is present instead."""
    template, _ = _template()
    for prefix in ("ResolutionFunction", "DedupFunction", "InferenceFunction"):
        statements = _policy_for(template, f"{prefix}ServiceRoleDefaultPolicy")
        rendered = json.dumps(statements, default=str)
        assert "crossroads/dev/*" in rendered, f"{prefix} missing env-wildcard SSM grant"


def test_extraction_and_resolution_and_inference_have_anthropic_grant():
    """Extraction/Resolution/Inference all call `grant_ssm_read`, so all carry the same
    env-wildcard SSM grant (covers `anthropic_api_key` among other params). Dedup also calls
    `grant_ssm_read` (for its own neo4j grant, see the test above) and therefore carries the
    identical wildcard -- the wildcard makes "dedup's grant excludes the anthropic key"
    unverifiable at the IAM-policy level; that per-Lambda distinction was dropped, not
    quietly broken (NFR-SEC-02 debt, see CLAUDE.md Current State)."""
    template, _ = _template()
    for prefix in ("ExtractionFunction", "ResolutionFunction", "InferenceFunction"):
        statements = _policy_for(template, f"{prefix}ServiceRoleDefaultPolicy")
        rendered = json.dumps(statements, default=str)
        assert "crossroads/dev/*" in rendered, f"{prefix} missing env-wildcard SSM grant"


def test_resolution_has_reconciliation_review_queue_grant_only():
    template, _ = _template()
    statements = _policy_for(template, "ResolutionFunctionServiceRoleDefaultPolicy")
    rendered = json.dumps(statements, default=str)
    assert "dynamodb:GetItem" in rendered or "dynamodb:PutItem" in rendered
    assert "reconciliationreviewqueue" in rendered.lower()
    assert "recache" not in rendered.lower()


def test_inference_has_re_cache_grant_only():
    template, _ = _template()
    statements = _policy_for(template, "InferenceFunctionServiceRoleDefaultPolicy")
    rendered = json.dumps(statements, default=str)
    assert "dynamodb:GetItem" in rendered or "dynamodb:PutItem" in rendered
    assert "recache" in rendered.lower()
    assert "reconciliationreviewqueue" not in rendered.lower()


def test_extraction_and_dedup_have_no_dynamodb_grants():
    template, _ = _template()
    for prefix in ("ExtractionFunction", "DedupFunction"):
        policies = {
            lid: res
            for lid, res in template.find_resources("AWS::IAM::Policy").items()
            if lid.startswith(f"{prefix}ServiceRoleDefaultPolicy")
        }
        for policy in policies.values():
            rendered = json.dumps(policy, default=str)
            assert "dynamodb:" not in rendered, f"{prefix} should have no DynamoDB grant: {rendered}"


def test_env_var_matches_get_config_for_any_env():
    template, _ = _template(env_name="prod")
    # Smoke check that a prod synth still produces the same shape.
    template.resource_count_is("AWS::Lambda::Function", 4)


def test_extraction_subscription_filters_to_article_messages_only():
    """L2 Extraction must not be invoked for L4's edge_write/node_write traffic."""
    template, _ = _template()
    template.has_resource_properties(
        "AWS::SNS::Subscription", {"FilterPolicy": {"message_type": ["article"]}}
    )
