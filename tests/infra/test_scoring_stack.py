"""CDK synth tests for ScoringStack.

Synth runs real Docker bundling (CLAUDE.md's "it must run").
"""

import json

import aws_cdk as cdk
import pytest
import yaml
from aws_cdk.assertions import Match, Template

from infra.stacks.foundation_stack import FoundationStack
from infra.stacks.scoring_stack import (
    _REQUIRED_KNOBS,
    _SCORING_YAML,
    ScoringStack,
    _state_id,
)
from src.common.graph.publish import MESSAGE_TYPE_EDGE_WRITE, MESSAGE_TYPE_NODE_WRITE
from src.scoring.sweep_handler import PHASES


def _synth(env_name: str = "dev") -> tuple[ScoringStack, Template]:
    app = cdk.App()
    foundation = FoundationStack(app, "TestFoundation", env_name=env_name)
    stack = ScoringStack(app, "TestScoring", env_name=env_name, foundation=foundation)
    return stack, Template.from_stack(stack)


def _template(env_name: str = "dev") -> Template:
    return _synth(env_name)[1]


def _actions_granted_to(stack: ScoringStack, template: Template, role) -> set[str]:
    """Every IAM action granted to exactly this role.

    Per-role, NOT stack-wide: a stack-wide action set says nothing about WHICH principal
    holds the grant, so it stays green when one of two Lambdas loses a grant the other
    still has -- which is how a sweep Lambda with no credentials would have shipped."""
    role_id = stack.get_logical_id(role.node.default_child)
    actions: set[str] = set()

    for policy in template.find_resources("AWS::IAM::Policy").values():
        refs = {
            r.get("Ref")
            for r in policy["Properties"].get("Roles", [])
            if isinstance(r, dict)
        }
        if role_id not in refs:
            continue
        for statement in policy["Properties"]["PolicyDocument"]["Statement"]:
            action = statement["Action"]
            actions.update(action if isinstance(action, list) else [action])
    return actions


def _properties_of(stack: ScoringStack, template: Template, fn) -> dict:
    """The synthesized properties of exactly this Lambda, by logical id."""
    logical_id = stack.get_logical_id(fn.node.default_child)
    return template.find_resources("AWS::Lambda::Function")[logical_id]["Properties"]


def _environment_of(stack: ScoringStack, template: Template, fn) -> dict[str, str]:
    return _properties_of(stack, template, fn).get("Environment", {}).get("Variables", {})


def _asl(template: Template) -> dict:
    """The state machine's DefinitionString, parsed.

    It is an `Fn::Join` mixing literal JSON with CloudFormation intrinsics. Each
    intrinsic is replaced by `@<logical-id>` so the result is parseable AND still says
    which resource it pointed at -- that is what lets a test assert the state machine
    invokes the SWEEP Lambda rather than merely "some Lambda"."""
    machines = template.find_resources("AWS::StepFunctions::StateMachine")
    definition = next(iter(machines.values()))["Properties"]["DefinitionString"]
    parts = definition["Fn::Join"][1] if isinstance(definition, dict) else [definition]

    def render(part) -> str:
        if isinstance(part, str):
            return part
        if "Fn::GetAtt" in part:
            return "@" + part["Fn::GetAtt"][0]
        if "Ref" in part:
            return "@" + part["Ref"]
        raise AssertionError(f"unhandled intrinsic in the definition: {part!r}")

    return json.loads("".join(render(p) for p in parts))


def test_event_lambda_subscription_filters_out_the_article_firehose():
    """Without this, the scoring Lambda is invoked on every article write forever.

    Asserted against the PUBLISHERS' own constants, not against two bare string literals.
    The filter policy and the publisher are opposite ends of one contract: a policy that
    allowlists a type no publisher stamps drops every message silently -- no error, no
    DLQ, no log -- and two independent literals cannot notice when one end moves.
    tests/scoring/test_pipeline_end_to_end.py holds the publishers to these same
    constants, so the two ends are now bound through a single source.
    """
    _template().has_resource_properties(
        "AWS::SNS::Subscription",
        {
            "FilterPolicy": {
                "message_type": [MESSAGE_TYPE_EDGE_WRITE, MESSAGE_TYPE_NODE_WRITE]
            }
        },
    )


def test_event_lambda_has_an_on_failure_destination():
    """SNS -> Lambda is an async invoke with NO DLQ by default."""
    _template().has_resource_properties(
        "AWS::Lambda::EventInvokeConfig",
        {"DestinationConfig": {"OnFailure": {"Destination": Match.any_value()}}},
    )


def test_sweep_runs_daily():
    _template().has_resource_properties(
        "AWS::Events::Rule", {"ScheduleExpression": Match.string_like_regexp(r"rate\(1 day\)")}
    )


def test_required_knobs_match_config_scoring_yaml_exactly():
    """`_REQUIRED_KNOBS` is the synth-time gate. If it drifts from the YAML, a knob can be
    added to config and silently never reach a Lambda -- which no other test would see,
    because every other knob test iterates `_REQUIRED_KNOBS` itself."""
    with open(_SCORING_YAML) as fh:
        in_yaml = set(yaml.safe_load(fh))
    assert set(_REQUIRED_KNOBS) == in_yaml


def test_every_knob_reaches_both_lambdas():
    """Per Lambda, and the WHOLE key set. The event handler and the sweep must agree on
    every knob: if one of them loses a value the other has, the two disagree on each
    tuned knob and scores flap between them on every pass."""
    stack, template = _synth()
    expected = {f"CROSSROADS_{k.upper()}" for k in _REQUIRED_KNOBS} | {"CROSSROADS_ENV"}
    for fn in (stack.event_fn, stack.sweep_fn):
        env = _environment_of(stack, template, fn)
        assert set(env) >= expected, f"{fn.node.id} is missing {expected - set(env)}"


def test_knob_values_come_from_the_yaml_not_the_code_defaults(monkeypatch, tmp_path):
    """Every value in config/scoring.yaml is byte-identical to knobs.py's fallback
    default (`kev_floor` 0.6, `decay_halflife_days` 180.0, ...), so asserting the real
    values cannot tell "the YAML was read" from "the YAML was ignored and knobs.py fell
    back at runtime". Point synth at a YAML matching no default and follow the values."""
    # Integers, not decimals: `9.10` round-trips through YAML as the float 9.1 and the
    # comparison fails on formatting rather than on anything the stack did.
    sentinel = {knob: str(1000 + i) for i, knob in enumerate(_REQUIRED_KNOBS)}
    source = tmp_path / "scoring.yaml"
    source.write_text("".join(f"{k}: {v}\n" for k, v in sentinel.items()))
    monkeypatch.setattr("infra.stacks.scoring_stack._SCORING_YAML", str(source))

    stack, template = _synth()
    for fn in (stack.event_fn, stack.sweep_fn):
        env = _environment_of(stack, template, fn)
        for knob, value in sentinel.items():
            assert env.get(f"CROSSROADS_{knob.upper()}") == value, (
                f"{fn.node.id} did not get {knob} from the YAML"
            )


def test_each_lambda_runs_its_own_handler_entrypoint():
    """Both Lambdas share one asset, so both entrypoints exist in both bundles and a swap
    deploys cleanly: the SNS-subscribed function would run the sweep handler and raise
    `unknown sweep phase: None` on every graph write, DLQ-ing the whole event stream."""
    stack, template = _synth()
    for fn, entrypoint in (
        (stack.event_fn, "src.scoring.event_handler.handler"),
        (stack.sweep_fn, "src.scoring.sweep_handler.handler"),
    ):
        assert _properties_of(stack, template, fn)["Handler"] == entrypoint


def test_both_lambdas_get_neo4j_ssm_read_but_no_sns_publish():
    """L4 computes and stores; it never publishes graph-writes. An sns:Publish grant
    here would be an over-grant with no code path behind it.

    Asserted per Lambda: both call get_driver(), so BOTH need the SSM read. Checking the
    stack-wide action set instead would let either one lose its grant unnoticed."""
    stack, template = _synth()
    for fn in (stack.event_fn, stack.sweep_fn):
        actions = _actions_granted_to(stack, template, fn.role)
        assert "ssm:GetParameter" in actions, f"{fn.node.id} has no Neo4j SSM read grant"
        assert not any(a.startswith("sns:Publish") for a in actions), (
            f"{fn.node.id} is over-granted sns:Publish"
        )


def test_state_machine_runs_every_phase_the_handler_declares():
    """Drives off the handler's own PHASES, NOT a literal list. A restated list silently
    goes stale the moment a phase is added -- `confidence_rescan` was added in Task 5.1
    and node confidence has no other repair path, so dropping it from the state machine
    would leave the accumulating score permanently unrepaired AND make `prune_flags`
    condemn entities on a stale confidence value."""
    definition = str(_template().find_resources("AWS::StepFunctions::StateMachine"))
    assert PHASES, "PHASES must not be empty or this test passes vacuously"
    for phase in PHASES:
        assert phase in definition, f"phase {phase!r} missing from the state machine"


def test_state_machine_wires_each_phase_in_declared_order_as_a_terminating_loop():
    """Membership is not wiring. Importing PHASES guarantees which phases exist; it
    guarantees nothing about the ORDER they reach the ASL in, what cursor they start
    from, which direction the loop condition points, or that the chain terminates --
    each of which was separately provable to be droppable with the suite green.

    ORDER IS LOAD-BEARING: `prune_flags` reads the confidence `confidence_rescan` and
    `decay` repair, so a reversed chain condemns entities on unrepaired values."""
    stack, template = _synth()
    assert PHASES, "PHASES must not be empty or this test passes vacuously"
    states = _asl(template)["States"]
    sweep_id = "@" + stack.get_logical_id(stack.sweep_fn.node.default_child)

    assert _asl(template)["StartAt"] == _state_id("Start", PHASES[0])

    for index, phase in enumerate(PHASES):
        start = _state_id("Start", phase)
        sweep = _state_id("Sweep", phase)
        done = _state_id("Done", phase)

        # Each phase restarts its scan from the beginning, discarding whatever the
        # scheduled event delivered. "" not null -- ASL cannot resolve a path to null.
        assert states[start]["Parameters"] == {"cursor": ""}
        assert states[start]["Next"] == sweep

        assert states[sweep]["Parameters"]["FunctionName"] == sweep_id, (
            f"{sweep} must invoke the sweep Lambda, not another function"
        )
        assert states[sweep]["Parameters"]["Payload"] == {
            "phase": phase,
            "cursor.$": "$.cursor",
        }
        # Dropping `cursor` here strands the next iteration's "$.cursor" against a
        # payload that no longer has one, failing the execution at runtime.
        assert set(states[sweep]["ResultSelector"]) == {"cursor.$", "done.$", "count.$"}
        assert states[sweep]["Next"] == done

        # done == false means "another page" -- inverted, every phase loops until the
        # 6h cap and no later phase ever runs.
        assert states[done]["Choices"] == [
            {"Variable": "$.done", "BooleanEquals": False, "Next": sweep}
        ]

        following = (
            _state_id("Start", PHASES[index + 1])
            if index + 1 < len(PHASES)
            else "SweepComplete"
        )
        assert states[done]["Default"] == following, (
            f"{phase} must be followed by {following}"
        )

    assert states["SweepComplete"]["Type"] == "Succeed"


def test_sweep_tasks_retry_throttles_and_transient_handler_failures():
    """CDK retries the four Lambda SERVICE exceptions on its own. A throttle and a
    transient Neo4j error are neither, and without these one blip aborts the whole daily
    sweep mid-phase -- every phase after it silently never runs."""
    states = _asl(_template())["States"]
    for phase in PHASES:
        retried = {
            error
            for retry in states[_state_id("Sweep", phase)]["Retry"]
            for error in retry["ErrorEquals"]
        }
        assert {"Lambda.TooManyRequestsException", "States.TaskFailed"} <= retried


def test_sweep_execution_is_capped_so_a_wedged_phase_cannot_run_forever():
    """CDK renders the state machine timeout INSIDE the ASL, not as a CFN property."""
    assert _asl(_template())["TimeoutSeconds"] == 21600


def test_event_dlq_is_named_per_environment():
    """Env-prefixed, matching the DynamoDB convention: the DLQ name is account-global, so
    an env-less name collides across environments in a shared account."""
    _template("prod").has_resource_properties(
        "AWS::SQS::Queue", {"QueueName": "crossroads-prod-scoring-event-dlq"}
    )


def test_scoring_yaml_is_missing_a_knob_fails_synth_loudly(monkeypatch, tmp_path):
    """A typo'd or deleted key must fail at synth, not silently fall back at runtime."""
    bad = tmp_path / "scoring.yaml"
    bad.write_text("kev_floor: 0.6\n")
    monkeypatch.setattr("infra.stacks.scoring_stack._SCORING_YAML", str(bad))
    with pytest.raises(ValueError, match="missing required scoring knob"):
        _template()
