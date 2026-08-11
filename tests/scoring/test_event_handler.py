import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.scoring import event_handler
from src.scoring.event_handler import _resolve_endpoint, handler
from src.scoring._shared import KEY_PROP_BY_LABEL, SCORED_LABELS
from src.scoring.knobs import RelevanceKnobs


def _sns(message: dict) -> dict:
    return {"Records": [{"Sns": {"Message": json.dumps(message)}}]}


def _wire(get_driver):
    """Make the patched driver behave like a real one.

    A bare MagicMock records `execute_write(fn)` without ever invoking `fn`, so the
    unit of work -- the `score_cve` call this module exists to dispatch -- would never
    run and could never be asserted on. Neo4j's real session runs it, so the double
    must too.
    """
    session = get_driver.return_value.session.return_value.__enter__.return_value
    # `*args/**kwargs` because the relevance path dispatches
    # `execute_write(_score_endpoint, key, knobs, now)` rather than a bare closure.
    session.execute_write.side_effect = lambda uow, *args, **kwargs: uow(
        MagicMock(), *args, **kwargs
    )


@patch("src.scoring.event_handler.score_cve")
@patch("src.scoring.event_handler.get_driver")
def test_node_write_on_a_scoring_input_triggers_severity(_driver, score):
    _wire(_driver)
    result = handler(
        _sns({"message_type": "node_write", "label": "CVE",
              "key": {"cve_id": "CVE-2026-1"},
              "changed_fields": ["exploited_in_wild"], "origin": "cisa-kev"}),
        None,
    )
    assert result["processed"] == 1
    assert score.called


@patch("src.scoring.event_handler.score_cve")
@patch("src.scoring.event_handler.get_driver")
def test_node_write_on_an_irrelevant_field_is_skipped(_driver, score):
    """changed_fields exists precisely so L4 does no graph work for a description edit."""
    _wire(_driver)
    result = handler(
        _sns({"message_type": "node_write", "label": "CVE",
              "key": {"cve_id": "CVE-2026-1"},
              "changed_fields": ["description"], "origin": "nvd"}),
        None,
    )
    assert result["skipped"] == 1
    assert not score.called


@patch("src.scoring.event_handler.stamp_significant_event")
@patch("src.scoring.event_handler.score_entity")
@patch("src.scoring.event_handler.score_cve")
@patch("src.scoring.event_handler.get_driver")
def test_new_exploited_by_edge_triggers_severity_on_the_start_cve(
    _driver, score, _entity, _stamp
):
    """FR-ES-03: adoption changed, so the CVE must be rescored.

    EXPLOITED_BY is also an assertion edge, so relevance runs on both endpoints too;
    that is Task 3.2's concern and is stubbed here to keep this test on severity.
    """
    _wire(_driver)
    handler(
        _sns({"message_type": "edge_write", "rel_type": "EXPLOITED_BY",
              "start_key": {"cve_id": "CVE-2026-1"},
              "end_key": {"merge_key": "apt-x"},
              "outcome": "created", "origin": "inferred"}),
        None,
    )
    assert score.call_args.kwargs["cve_id"] == "CVE-2026-1"


@patch("src.scoring.event_handler.score_cve")
@patch("src.scoring.event_handler.get_driver")
def test_a_non_exploited_by_edge_does_not_trigger_severity(_driver, score):
    """The rel_type guard must do the rejecting -- not the absence of a cve_id.

    USES starts at a ThreatActor, so it has no `cve_id` to find and would be rejected
    even with the guard removed. CATEGORIZED_AS is the case that actually pins the
    guard: it is CVE->CWE (technical-specification.md §3.2), so its start_key DOES
    carry a cve_id. Nothing publishes it as an edge_write today, which is exactly why
    the guard needs a test rather than a live incident.
    """
    _wire(_driver)
    handler(
        _sns({"message_type": "edge_write", "rel_type": "USES",
              "start_key": {"merge_key": "apt-x"},
              "end_key": {"technique_id": "T1059"},
              "outcome": "created", "origin": "inferred"}),
        None,
    )
    assert not score.called

    handler(
        _sns({"message_type": "edge_write", "rel_type": "CATEGORIZED_AS",
              "start_key": {"cve_id": "CVE-2026-1"},
              "end_key": {"cwe_id": "CWE-79"},
              "outcome": "created", "origin": "nvd"}),
        None,
    )
    assert not score.called


@patch("src.scoring.event_handler.score_cve")
@patch("src.scoring.event_handler.get_driver")
def test_a_non_cve_node_write_is_skipped(_driver, score):
    """Tasks 3.2/4.1 extend this handler with ThreatActor/MalwareFamily traffic. If the
    label guard is loosened to let relevance through, severity must still not fire.

    The key deliberately carries a `cve_id` even though the label is not CVE. That is
    contrived -- a real node_write's key is the node's own natural key -- but it is the
    only way to isolate the LABEL guard: with a realistic `{merge_key: ...}` the later
    `cve_id` lookup does the rejecting, and removing the label guard entirely still
    passes. Verified by fault injection.
    """
    _wire(_driver)
    result = handler(
        _sns({"message_type": "node_write", "label": "ThreatActor",
              "key": {"merge_key": "apt-x", "cve_id": "CVE-2026-1"},
              "changed_fields": ["cvss_score"], "origin": "inferred"}),
        None,
    )
    assert result == {"processed": 0, "skipped": 1}
    assert not score.called


@patch("src.scoring.event_handler.score_cve")
@patch("src.scoring.event_handler.get_driver")
def test_an_exploited_by_edge_without_a_cve_start_key_is_skipped(_driver, score):
    """The rel_type guard passes here, so this pins the separate start_key fallthrough."""
    _wire(_driver)
    result = handler(
        _sns({"message_type": "edge_write", "rel_type": "EXPLOITED_BY",
              "start_key": {"merge_key": "not-a-cve"},
              "end_key": {"merge_key": "apt-x"},
              "outcome": "created", "origin": "inferred"}),
        None,
    )
    assert result == {"processed": 0, "skipped": 1}
    assert not score.called


@patch("src.scoring.event_handler.score_cve")
@patch("src.scoring.event_handler.get_driver")
def test_counters_accumulate_across_a_multi_record_batch(_driver, score):
    """Every other test sends one record, so nothing pins that the counters add up
    rather than overwrite. A refactor to `processed = int(did)` would pass without this."""
    _wire(_driver)
    scoring = {"message_type": "node_write", "label": "CVE",
               "key": {"cve_id": "CVE-2026-1"},
               "changed_fields": ["cvss_score"], "origin": "nvd"}
    ignored = {"message_type": "node_write", "label": "CVE",
               "key": {"cve_id": "CVE-2026-2"},
               "changed_fields": ["description"], "origin": "nvd"}
    event = {"Records": [
        {"Sns": {"Message": json.dumps(m)}} for m in (scoring, ignored, scoring)
    ]}

    result = handler(event, None)

    assert result == {"processed": 2, "skipped": 1}
    assert score.call_count == 2


@patch("src.scoring.event_handler.get_driver")
def test_an_article_message_is_skipped_not_an_error(_driver):
    """Defence in depth: the SNS filter policy should already prevent delivery, but a
    misconfigured or removed policy must degrade to a no-op, never a DLQ storm."""
    _wire(_driver)
    result = handler(_sns({"message_type": "article", "node_label": "Article"}), None)
    assert result == {"processed": 0, "skipped": 1}


@patch("src.scoring.event_handler.refine_from_mention")
@patch("src.scoring.event_handler.stamp_significant_event")
@patch("src.scoring.event_handler.score_entity")
@patch("src.scoring.event_handler._resolve_endpoint", return_value=("ThreatActor", "apt-x"))
@patch("src.scoring.event_handler.get_driver")
def test_mentions_edge_drives_relevance_on_the_end_entity(
    _driver, _resolve, score, stamp, _refine
):
    """A MENTIONS start endpoint is an Article, never a scored entity -- only the end
    endpoint may be scored."""
    _wire(_driver)
    handler(
        _sns({"message_type": "edge_write", "rel_type": "MENTIONS",
              "start_key": {"source_guid_key": "src::1"},
              "end_key": {"merge_key": "apt-x"},
              "outcome": "created", "origin": None}),
        None,
    )
    assert score.called
    assert stamp.called
    # Twice: once for the confidence refinement, once for the relevance recompute --
    # and BOTH on the end endpoint. The start endpoint is an Article and must never be
    # handed to the entity resolver.
    assert _resolve.call_count == 2
    assert [c.args[1] for c in _resolve.call_args_list] == [{"merge_key": "apt-x"}] * 2


@patch("src.scoring.event_handler.refine_from_mention")
@patch("src.scoring.event_handler.stamp_significant_event")
@patch("src.scoring.event_handler.score_entity")
@patch("src.scoring.event_handler._resolve_endpoint", return_value=("ThreatActor", "apt-x"))
@patch("src.scoring.event_handler.get_driver")
def test_fr_es_08_a_mention_refines_the_mentioned_nodes_confidence(
    _driver, _resolve, _score, _stamp, refine
):
    """FR-ES-08 is driven from the MENTIONS path: the article that carries the evidence
    is the start endpoint, and its key is what resolves credibility and cluster."""
    _wire(_driver)
    handler(
        _sns({"message_type": "edge_write", "rel_type": "MENTIONS",
              "start_key": {"source_guid_key": "src::1"},
              "end_key": {"merge_key": "apt-x"},
              "outcome": "created", "origin": None}),
        None,
    )
    assert refine.call_args.kwargs == {
        "label": "ThreatActor", "key": "apt-x", "article_key": "src::1"
    }


@patch("src.scoring.event_handler.refine_from_mention")
@patch("src.scoring.event_handler.stamp_significant_event")
@patch("src.scoring.event_handler.score_entity")
@patch("src.scoring.event_handler._resolve_endpoint", return_value=("ThreatActor", "apt-x"))
@patch("src.scoring.event_handler.get_driver")
def test_a_mention_without_an_article_key_refines_nothing(
    _driver, _resolve, score, _stamp, refine
):
    """Without the article there is no credibility, no extraction confidence and no
    cluster, so there is no contribution to make -- but relevance still runs."""
    _wire(_driver)
    handler(
        _sns({"message_type": "edge_write", "rel_type": "MENTIONS",
              "start_key": {"merge_key": "not-an-article"},
              "end_key": {"merge_key": "apt-x"},
              "outcome": "created", "origin": None}),
        None,
    )
    assert not refine.called
    assert score.called


@patch("src.scoring.event_handler.refine_from_mention")
@patch("src.scoring.event_handler.stamp_significant_event")
@patch("src.scoring.event_handler.score_entity")
@patch("src.scoring.event_handler._resolve_endpoint", return_value=None)
@patch("src.scoring.event_handler.get_driver")
def test_an_unresolvable_mention_endpoint_refines_nothing(
    _driver, _resolve, _score, _stamp, refine
):
    """Same rule as scoring: an endpoint L4 cannot name is skipped, never guessed."""
    _wire(_driver)
    result = handler(
        _sns({"message_type": "edge_write", "rel_type": "MENTIONS",
              "start_key": {"source_guid_key": "src::1"},
              "end_key": {"merge_key": "ambiguous"},
              "outcome": "created", "origin": None}),
        None,
    )
    assert not refine.called
    assert result == {"processed": 0, "skipped": 1}


@patch("src.scoring.event_handler.refine_from_mention", return_value=None)
@patch("src.scoring.event_handler.stamp_significant_event")
@patch("src.scoring.event_handler.score_entity", return_value=None)
@patch("src.scoring.event_handler._resolve_endpoint", return_value=("ThreatActor", "apt-x"))
@patch("src.scoring.event_handler.get_driver")
def test_a_mention_of_a_canonical_node_is_not_counted_as_refinement(
    _driver, _resolve, _score, _stamp, _refine
):
    """refine_from_mention returns None for a canonical node, and that must not read as
    work done -- otherwise every mention of every canonical entity reports processed."""
    _wire(_driver)
    result = handler(
        _sns({"message_type": "edge_write", "rel_type": "MENTIONS",
              "start_key": {"source_guid_key": "src::1"},
              "end_key": {"merge_key": "apt-x"},
              "outcome": "created", "origin": None}),
        None,
    )
    assert result == {"processed": 0, "skipped": 1}


@patch("src.scoring.event_handler.stamp_significant_event")
@patch("src.scoring.event_handler.score_entity")
@patch("src.scoring.event_handler.score_cve")
@patch("src.scoring.event_handler._resolve_endpoint", return_value=("ThreatActor", "apt-x"))
@patch("src.scoring.event_handler.get_driver")
def test_assertion_edge_scores_both_endpoints(_driver, _resolve, _cve, score, _stamp):
    """Centrality moved at BOTH ends, so both need rescoring."""
    _wire(_driver)
    handler(
        _sns({"message_type": "edge_write", "rel_type": "ATTRIBUTED_TO",
              "start_key": {"merge_key": "camp-x"},
              "end_key": {"merge_key": "apt-x"},
              "outcome": "created", "origin": "inferred"}),
        None,
    )
    assert score.call_count == 2


@patch("src.scoring.event_handler.refine_from_mention")
@patch("src.scoring.event_handler.stamp_significant_event")
@patch("src.scoring.event_handler.score_entity")
@patch("src.scoring.event_handler._resolve_endpoint", return_value=("ThreatActor", "apt-x"))
@patch("src.scoring.event_handler.get_driver")
def test_the_clock_is_stamped_before_relevance_is_computed(
    _driver, _resolve, score, stamp, _refine
):
    """score_entity reads last_significant_event; scoring first would store a novelty
    computed against the pre-event clock until the next sweep."""
    _wire(_driver)
    calls = []
    stamp.side_effect = lambda *a, **k: calls.append("stamp")
    score.side_effect = lambda *a, **k: calls.append("score")
    handler(
        _sns({"message_type": "edge_write", "rel_type": "MENTIONS",
              "start_key": {"source_guid_key": "src::1"},
              "end_key": {"merge_key": "apt-x"},
              "outcome": "created", "origin": None}),
        None,
    )
    assert calls == ["stamp", "score"]


@patch("src.scoring.event_handler.stamp_significant_event")
@patch("src.scoring.event_handler.score_entity")
@patch("src.scoring.event_handler._resolve_endpoint", return_value=("ThreatActor", "apt-x"))
@patch("src.scoring.event_handler.get_driver")
def test_a_structural_edge_drives_no_relevance(_driver, _resolve, score, stamp):
    """CATEGORIZED_AS is structural (spec C3), not an assertion and not a mention, so it
    moves neither centrality nor the novelty clock."""
    _wire(_driver)
    result = handler(
        _sns({"message_type": "edge_write", "rel_type": "CATEGORIZED_AS",
              "start_key": {"cve_id": "CVE-2026-1"},
              "end_key": {"cwe_id": "CWE-79"},
              "outcome": "created", "origin": "nvd"}),
        None,
    )
    assert result == {"processed": 0, "skipped": 1}
    assert not score.called
    assert not stamp.called


# --- _resolve_endpoint against a real graph -------------------------------------------
# Deliberately NOT mocked: label resolution is the part that can silently score the
# WRONG entity, and `merge_key` is shared by three labels, so only the graph can say
# which one a key belongs to.


@pytest.fixture
def driver():
    d = get_driver()
    d.verify_connectivity()
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
        s.run(
            "MERGE (a:ThreatActor {merge_key:'apt-res-test'}) SET a.test_fixture = true "
            "MERGE (m:MalwareFamily {merge_key:'mal-res-test'}) SET m.test_fixture = true "
            "MERGE (c:Campaign {merge_key:'camp-res-test'}) SET c.test_fixture = true"
        ).consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


def _resolve(driver, endpoint_key):
    with driver.session() as s:
        return s.execute_read(lambda tx: _resolve_endpoint(tx, endpoint_key))


@pytest.mark.parametrize(
    "key,expected",
    [
        ("apt-res-test", "ThreatActor"),
        ("mal-res-test", "MalwareFamily"),
        ("camp-res-test", "Campaign"),
    ],
)
def test_merge_key_is_disambiguated_by_asking_the_graph(driver, key, expected):
    assert _resolve(driver, {"merge_key": key}) == (expected, key)


def test_an_unambiguous_key_property_needs_no_graph_lookup(driver):
    """cve_id belongs to exactly one scored label, so resolution must not depend on the
    node existing."""
    assert _resolve(driver, {"cve_id": "CVE-2026-9999"}) == ("CVE", "CVE-2026-9999")
    assert _resolve(driver, {"value_type_key": "1.2.3.4::ipv4"}) == (
        "IOC",
        "1.2.3.4::ipv4",
    )


def test_an_unknown_merge_key_resolves_to_nothing(driver):
    assert _resolve(driver, {"merge_key": "no-such-entity"}) is None


def test_a_merge_key_on_an_unscored_label_resolves_to_nothing(driver):
    with driver.session() as s:
        s.run(
            "MERGE (t:TTP {merge_key:'ttp-res-test'}) SET t.test_fixture = true"
        ).consume()
    assert _resolve(driver, {"merge_key": "ttp-res-test"}) is None


def test_an_unscored_key_property_resolves_to_nothing(driver):
    assert _resolve(driver, {"technique_id": "T1059"}) is None


def test_a_multi_property_or_empty_key_resolves_to_nothing(driver):
    assert _resolve(driver, {"merge_key": "apt-res-test", "cve_id": "CVE-2026-1"}) is None
    assert _resolve(driver, {}) is None
    assert _resolve(driver, None) is None


def test_a_merge_key_shared_by_two_labels_declines_rather_than_guessing(driver):
    """`merge_key` is a lowercased normalized NAME, and its UNIQUE constraints are
    PER-LABEL, so a ThreatActor and a MalwareFamily can both legitimately answer to
    'lazarus' -- an ordinary naming pattern in threat intel, not a contrived case.

    The message names the endpoint by key ALONE, so L4 genuinely cannot tell which entity
    the edge touched. Picking one (which `.single()` did, arbitrarily, by creation order)
    spikes the novelty of an entity that had no news, and the daily sweep cannot repair
    that -- it recomputes relevance but never writes last_significant_event.
    """
    with driver.session() as s:
        s.run(
            "MERGE (m:MalwareFamily {merge_key:'lazarus'}) SET m.test_fixture = true "
            "MERGE (a:ThreatActor {merge_key:'lazarus'}) SET a.test_fixture = true"
        ).consume()

    assert _resolve(driver, {"merge_key": "lazarus"}) is None


def test_resolution_is_constrained_to_the_merge_key_labels(driver):
    """Derived from _shared rather than hand-listed, and the query is label-constrained --
    a bare `MATCH (n {merge_key: $key})` is an AllNodesScan of the whole graph, run on
    every MENTIONS write."""
    assert set(event_handler._MERGE_KEY_LABELS) == {
        "ThreatActor",
        "MalwareFamily",
        "Campaign",
    }
    for label in event_handler._MERGE_KEY_LABELS:
        assert f":{label}" in event_handler._RESOLVE_MERGE_KEY or (
            label in event_handler._RESOLVE_MERGE_KEY
        )
    assert "MATCH (n:" in event_handler._RESOLVE_MERGE_KEY


def test_score_endpoint_stamps_and_scores_against_a_real_graph(driver):
    """Every dispatch test above mocks _resolve_endpoint, score_entity AND
    stamp_significant_event at once, so the stamp->score integration is covered only by
    call ordering on mocks. This drives the real thing: the stamp must be visible to
    score_entity inside the SAME transaction, or novelty is computed against the
    pre-event clock and a stale value is stored until the next sweep.
    """
    with driver.session() as s:
        s.run(
            "MATCH (a:ThreatActor {merge_key:'apt-res-test'}) "
            "SET a.last_significant_event = datetime('2020-01-01T00:00:00Z')"
        ).consume()

    now = datetime(2026, 7, 30, tzinfo=timezone.utc)
    with driver.session() as s:
        did = s.execute_write(
            event_handler._score_endpoint,
            {"merge_key": "apt-res-test"},
            RelevanceKnobs.from_config(),
            now,
        )

    assert did is True
    with driver.session() as s:
        row = s.run(
            "MATCH (a:ThreatActor {merge_key:'apt-res-test'}) "
            "RETURN a.last_significant_event AS lse, a.relevance_score AS score"
        ).single()
    assert row["lse"].to_native().replace(tzinfo=timezone.utc) == now
    # Clock stamped to `now` => age 0 => novelty 1.0 => score == w_novelty.
    assert row["score"] == pytest.approx(RelevanceKnobs.from_config().w_novelty)


# --- Task 5.0: the self-describing graph-writes message ----------------------------


def _resolve_labelled(driver, endpoint_key, label):
    with driver.session() as s:
        return s.execute_read(lambda tx: _resolve_endpoint(tx, endpoint_key, label))


def test_a_labelled_message_resolves_the_merge_key_collision(driver):
    """The counterpart to `..._declines_rather_than_guessing`: same ambiguous graph, but
    the message now names the label, so L4 resolves it instead of skipping."""
    with driver.session() as s:
        s.run(
            "MERGE (m:MalwareFamily {merge_key:'lazarus-5-0'}) SET m.test_fixture = true "
            "MERGE (a:ThreatActor {merge_key:'lazarus-5-0'}) SET a.test_fixture = true"
        ).consume()

    key = {"merge_key": "lazarus-5-0"}
    assert _resolve_labelled(driver, key, "ThreatActor") == ("ThreatActor", "lazarus-5-0")
    assert _resolve_labelled(driver, key, "MalwareFamily") == ("MalwareFamily", "lazarus-5-0")
    # ...and the no-label fallback still declines, which is what keeps the field additive.
    assert _resolve(driver, key) is None


def test_a_label_inconsistent_with_the_key_resolves_to_nothing(driver):
    """The label is trusted, not obeyed. A CVE endpoint carrying a `merge_key` is a
    malformed message; resolving it would score whichever node the wrong prop matched."""
    assert _resolve_labelled(driver, {"merge_key": "anything"}, "CVE") is None
    assert _resolve_labelled(driver, {"cve_id": "CVE-2026-1"}, "ThreatActor") is None
    # A label outside SCORED_LABELS is not scorable even if the key is well-formed.
    # NOTE: today this line is rejected by the KEY_PROP half of the guard as much as by the
    # SCORED_LABELS half -- "Article" has no merge_key. The invariant that keeps the two
    # equivalent is pinned separately below; it is not proven here.
    assert _resolve_labelled(driver, {"merge_key": "anything"}, "Article") is None


def test_every_key_prop_label_is_also_a_scored_label():
    """`_resolve_endpoint` guards on BOTH `label in SCORED_LABELS` and the key property.
    Those are only equivalent because the two maps currently cover the same labels.

    Adding an unscored label to KEY_PROP_BY_LABEL (say `Article: source_guid_key`) would
    make the key-property half start accepting it, and only the SCORED_LABELS half would
    stand between a MENTIONS message and a relevance_score written onto an Article. No
    resolve test can express that case while the maps agree -- so pin the agreement, and
    whoever breaks it is sent here to look at the guard.
    """
    assert set(KEY_PROP_BY_LABEL) == set(SCORED_LABELS)


def _edge_message(rel_type, **overrides):
    """An edge_write shaped for whichever branch of `_handle_edge_write` handles it.

    MENTIONS and the assertion types are SEPARATE branches: MENTIONS scores only its end
    endpoint, an assertion scores both. Tests that pin stamping or the event clock must
    drive both, or the assertion branch keeps its own copy of the behaviour unpinned.
    """
    if rel_type == "MENTIONS":
        message = {
            "message_type": "edge_write", "rel_type": "MENTIONS",
            "start_key": {"source_guid_key": "art-1"},
            "end_key": {"merge_key": "apt-x"}, "end_label": "ThreatActor",
        }
    else:
        message = {
            "message_type": "edge_write", "rel_type": rel_type,
            "start_key": {"merge_key": "camp-x"}, "start_label": "Campaign",
            "end_key": {"merge_key": "apt-x"}, "end_label": "ThreatActor",
        }
    message.update(overrides)
    return message


# One MENTIONS + one assertion type. ATTRIBUTED_TO rather than EXPLOITED_BY, so the
# severity side-path stays out of these assertions.
_BOTH_BRANCHES = ["MENTIONS", "ATTRIBUTED_TO"]


@pytest.mark.parametrize("rel_type", _BOTH_BRANCHES)
@pytest.mark.parametrize(
    "outcome,should_stamp",
    [
        ("matched", False),      # the ONLY value that means "no new evidence"
        ("created", True),
        ("updated", True),       # new cluster on an existing edge -- genuine news
        ("resolved", True),      # L2 resolution's vocabulary
        ("provisional", True),   # ditto
        ("inferred", True),      # the old hardcoded literal
        (None, True),            # message predates the field
    ],
)
@patch("src.scoring.event_handler.stamp_significant_event")
@patch("src.scoring.event_handler.score_entity")
@patch("src.scoring.event_handler.refine_from_mention")
@patch("src.scoring.event_handler._resolve_endpoint", return_value=("ThreatActor", "apt-x"))
@patch("src.scoring.event_handler.get_driver")
def test_novelty_stamping_is_a_deny_list_on_matched(
    _driver, _resolve, _refine, _entity, stamp, outcome, should_stamp, rel_type
):
    """FR-ES-06. An allow-list on `created` would stamp NOTHING on the MENTIONS path,
    because L2 resolution never emits `created` -- see `_is_newsworthy`."""
    _wire(_driver)
    message = _edge_message(rel_type, end_key={"merge_key": "apt-deny-list"})
    if outcome is not None:
        message["outcome"] = outcome

    handler(_sns(message), None)

    assert stamp.called is should_stamp


@patch("src.scoring.event_handler.stamp_significant_event")
@patch("src.scoring.event_handler.score_entity")
@patch("src.scoring.event_handler.refine_from_mention")
@patch("src.scoring.event_handler._resolve_endpoint", return_value=("ThreatActor", "apt-x"))
@patch("src.scoring.event_handler.get_driver")
def test_a_matched_outcome_still_rescores_the_entity(
    _driver, _resolve, _refine, entity, stamp
):
    """Skipping the STAMP must not skip the SCORE: a re-emitted edge can carry no news
    and still have moved the entity's degree or credibility."""
    _wire(_driver)
    handler(
        _sns({"message_type": "edge_write", "rel_type": "MENTIONS",
              "start_key": {"source_guid_key": "art-1"},
              "end_key": {"merge_key": "apt-still-scored"},
              "end_label": "ThreatActor", "outcome": "matched"}),
        None,
    )
    assert not stamp.called
    assert entity.called


@pytest.mark.parametrize("rel_type,stamps_per_delivery", [("MENTIONS", 1), ("ATTRIBUTED_TO", 2)])
@patch("src.scoring.event_handler.stamp_significant_event")
@patch("src.scoring.event_handler.score_entity")
@patch("src.scoring.event_handler.refine_from_mention")
@patch("src.scoring.event_handler._resolve_endpoint", return_value=("ThreatActor", "apt-x"))
@patch("src.scoring.event_handler.get_driver")
def test_event_time_is_used_and_a_redelivery_does_not_advance_the_clock(
    _driver, _resolve, _refine, _entity, stamp, rel_type, stamps_per_delivery
):
    """NFR-REL-02. `datetime.now()` per DELIVERY made the stamp non-idempotent end to
    end: SNS redelivering one message walked the novelty clock forward every time."""
    _wire(_driver)
    event_time = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)
    message = _edge_message(
        rel_type,
        end_key={"merge_key": "apt-redelivery"},
        outcome="created",
        event_time=event_time.isoformat(),
    )

    handler(_sns(message), None)
    handler(_sns(message), None)

    stamped = [c.kwargs["at"] for c in stamp.call_args_list]
    # An assertion stamps both endpoints, so the count differs per branch; what must
    # hold on both is that the SECOND delivery replays the same instant.
    assert stamped == [event_time] * (2 * stamps_per_delivery)


@pytest.mark.parametrize("raw", [None, "", "not-a-timestamp", "2026-07-01T12:00:00"])
@patch("src.scoring.event_handler.stamp_significant_event")
@patch("src.scoring.event_handler.score_entity")
@patch("src.scoring.event_handler.refine_from_mention")
@patch("src.scoring.event_handler._resolve_endpoint", return_value=("ThreatActor", "apt-x"))
@patch("src.scoring.event_handler.get_driver")
def test_unusable_event_time_falls_back_to_now(
    _driver, _resolve, _refine, _entity, stamp, raw
):
    """Absent, malformed, or NAIVE. The naive case matters: `stamp_significant_event`
    rejects a naive datetime outright, so passing it through would fail the record."""
    _wire(_driver)
    before = datetime.now(timezone.utc)
    message = {
        "message_type": "edge_write", "rel_type": "MENTIONS",
        "start_key": {"source_guid_key": "art-1"},
        "end_key": {"merge_key": "apt-fallback"}, "end_label": "ThreatActor",
        "outcome": "created",
    }
    if raw is not None:
        message["event_time"] = raw

    handler(_sns(message), None)

    at = stamp.call_args.kwargs["at"]
    assert at.tzinfo is not None
    assert before <= at <= datetime.now(timezone.utc)


@patch("src.scoring.event_handler.score_cve")
@patch("src.scoring.event_handler.stamp_significant_event")
@patch("src.scoring.event_handler.score_entity")
@patch("src.scoring.event_handler.refine_from_mention")
@patch("src.scoring.event_handler._resolve_endpoint", return_value=("ThreatActor", "apt-x"))
@patch("src.scoring.event_handler.get_driver")
def test_the_messages_labels_are_forwarded_to_the_resolver(
    _driver, resolve, _refine, _entity, _stamp, _cve
):
    """Pins the WIRING, not the resolver. Every other test here patches
    `_resolve_endpoint`, so `_handle_edge_write` could quietly stop passing the label and
    they would all still pass -- the endpoint would silently fall back to the ambiguous
    graph lookup, which is the exact Critical Task 5.0 exists to close.
    """
    _wire(_driver)
    handler(
        _sns({"message_type": "edge_write", "rel_type": "MENTIONS",
              "start_key": {"source_guid_key": "art-1"},
              "end_key": {"merge_key": "lz"}, "end_label": "MalwareFamily"}),
        None,
    )
    # Both the refine and the score path must carry it.
    assert [c.args[2] for c in resolve.call_args_list] == ["MalwareFamily", "MalwareFamily"]

    resolve.reset_mock()
    handler(
        _sns({"message_type": "edge_write", "rel_type": "EXPLOITED_BY",
              "start_key": {"cve_id": "CVE-2026-1"}, "start_label": "CVE",
              "end_key": {"merge_key": "lz"}, "end_label": "ThreatActor"}),
        None,
    )
    # Each endpoint gets ITS OWN label, in order -- not both ends given one of them.
    assert [c.args[2] for c in resolve.call_args_list] == ["CVE", "ThreatActor"]
