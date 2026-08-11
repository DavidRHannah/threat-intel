"""Cross-stage-boundary tests (spec §8 tier 4).

Every message here is produced by the REAL publisher (captured from a mocked SNS client)
and fed into the REAL handler -- never hand-constructed at the boundary. A mismatch
between what a publisher emits and what a consumer expects is invisible to any test that
builds its own input, which is precisely how L2 shipped a pipeline that was
non-functional past Extraction.

Two boundaries are crossed here, and they are crossed differently on purpose:

  * L1/L2 -> L4 via the `graph-writes` TOPIC. `_capture` runs a real publisher against a
    mocked SNS client, wraps the captured body in the SNS->Lambda envelope AWS actually
    delivers, and hands it to `src.scoring.event_handler.handler`. Nothing in between is
    written by hand.
  * L2 -> L4 via the GRAPH ITSELF. `first_seen` is not carried by any message: L2's
    resolver writes it onto the node and L4's prune scan reads it back a quarter later.
    That contract is proved by running the real writer and the real scan against one
    database, with no message involved (see the FR-ES-10 test at the bottom).

Assertions are on GRAPH STATE, never on the handler's `processed` count. `processed` only
says a dispatch happened -- it is 1 whether the CVE was scored correctly, scored wrongly,
or scored with a stale formula. Each test therefore asserts the property is absent before
and correct after.
"""
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.common.config import get_config
from src.common.graph.publish import (
    MESSAGE_TYPE_EDGE_WRITE,
    MESSAGE_TYPE_NODE_WRITE,
    publish_graph_write,
    publish_node_write,
)
from src.common.neo4j_driver import close_driver, get_driver
from src.nlp.messages import RawMention
from src.nlp.resolution.fuzzy import _create_provisional
from src.nlp.resolution.handler import _process_article
from src.scoring.confidence import flag_pruning_batch
from src.scoring.event_handler import handler
from src.scoring.knobs import ConfidenceKnobs


@pytest.fixture
def topic_env(monkeypatch):
    """The publishers read the topic ARN through `get_config`, which is lru_cached, so
    the cache must be cleared on the way IN and on the way OUT -- otherwise a test that
    runs after one of these inherits a stale ARN, or worse, a cached miss."""
    monkeypatch.setenv("CROSSROADS_GRAPH_WRITES_TOPIC_ARN", "arn:aws:sns:x:1:graph-writes")
    get_config.cache_clear()
    yield
    get_config.cache_clear()


@pytest.fixture
def driver(topic_env):
    d = get_driver()
    d.verify_connectivity()
    _wipe(d)
    yield d
    _wipe(d)
    close_driver()


def _wipe(d):
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()


def _capture(publish_call) -> dict:
    """Run a REAL publisher against a mocked SNS client and shape the captured message
    into the SNS->Lambda event envelope AWS actually delivers.

    Only `boto3.client` is mocked. The body, the attributes, and every defaulted field
    (`event_time`, the labels) are produced by the publisher under test, so a publisher
    that stops emitting a field the handler needs breaks these tests rather than being
    papered over by a hand-written dict.
    """
    sns = MagicMock()
    with patch("boto3.client", return_value=sns):
        publish_call()
    call = sns.publish.call_args
    return {
        "body": json.loads(call.kwargs["Message"]),
        "attributes": call.kwargs["MessageAttributes"],
        "event": {"Records": [{"Sns": {"Message": call.kwargs["Message"]}}]},
    }


def _seed_article(driver, article_id: str) -> None:
    """`write_mentions_edge` -> `merge_relationship` is MATCH-only on both endpoints, so
    the Article must already exist. In production L1 writes it before L2 ever resolves a
    mention against it; here that upstream write is the fixture."""
    with driver.session() as s:
        s.run(
            "MERGE (a:Article {source_guid_key: $k}) SET a.test_fixture = true",
            k=article_id,
        ).consume()


def _flag_fixture(driver, merge_key: str) -> None:
    """Mark the node the REAL writer created so the fixture's wipe reclaims it. Applied
    after the fact on purpose: passing `test_fixture` into `_create_provisional` is
    impossible, which is the point -- the node under test is built by production code."""
    with driver.session() as s:
        s.run(
            "MATCH (n:ThreatActor {merge_key:$k}) SET n.test_fixture = true", k=merge_key
        ).consume()


def _prop(driver, cypher, **params):
    with driver.session() as s:
        row = s.run(cypher, **params).single()
    return None if row is None else row[0]


# --- L1 -> L4: node_write -------------------------------------------------------------


def test_kev_node_write_flows_through_to_a_stored_severity_band(driver):
    """A CISA-KEV `exploited_in_wild` flip, published by the real publisher, reaches the
    real handler and lands a severity band on the CVE (FR-ES-03 + FR-ES-04)."""
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-E2E-1'}) SET c.test_fixture = true, "
            "c.cvss_score = 9.8, c.epss_score = 0.9, c.exploited_in_wild = true"
        ).consume()

    band_before = _prop(
        driver, "MATCH (c:CVE {cve_id:'CVE-2026-E2E-1'}) RETURN c.severity_band"
    )
    assert band_before is None, "fixture must start unscored or the test proves nothing"

    captured = _capture(lambda: publish_node_write(
        label="CVE", key={"cve_id": "CVE-2026-E2E-1"},
        changed_fields=["exploited_in_wild"], origin="cisa-kev",
    ))
    handler(captured["event"], None)

    # Graph state, not `processed`: a dispatch that scored nothing also returns 1.
    #
    # `high`, not `critical`, and that is the correct answer: this CVE has no
    # EXPLOITED_BY edges, so the adoption term is 0 and the score is
    # 0.3*0.98 + 0.5*1.0 + 0.2*0 = 0.794 -- just under the 0.8 critical band. KEV alone
    # cannot reach critical without exploiters, which is exactly what severity-design.md
    # Part 2 says it should do.
    assert _prop(
        driver, "MATCH (c:CVE {cve_id:'CVE-2026-E2E-1'}) RETURN c.severity_band"
    ) == "high"
    assert _prop(
        driver, "MATCH (c:CVE {cve_id:'CVE-2026-E2E-1'}) RETURN c.severity_adoption"
    ) == 0.0
    # FR-ES-04's guarantee: a KEV-listed CVE never scores below the 0.6 floor.
    assert _prop(
        driver, "MATCH (c:CVE {cve_id:'CVE-2026-E2E-1'}) RETURN c.severity_score"
    ) >= 0.6


def test_node_write_for_an_unrelated_field_scores_nothing(driver):
    """The `changed_fields` filter is real, not decorative: a property change outside
    {cvss_score, epss_score, exploited_in_wild} must leave the CVE unscored."""
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-E2E-1B'}) SET c.test_fixture = true, "
            "c.cvss_score = 9.8, c.epss_score = 0.9, c.exploited_in_wild = true"
        ).consume()

    captured = _capture(lambda: publish_node_write(
        label="CVE", key={"cve_id": "CVE-2026-E2E-1B"},
        changed_fields=["description"], origin="nvd",
    ))
    handler(captured["event"], None)

    assert _prop(
        driver, "MATCH (c:CVE {cve_id:'CVE-2026-E2E-1B'}) RETURN c.severity_band"
    ) is None


# --- L2/L3 -> L4: edge_write ----------------------------------------------------------


def test_exploited_by_edge_write_flows_through_to_severity_and_relevance(driver):
    """One `EXPLOITED_BY` write moves THREE things across the boundary: the CVE's
    severity adoption term, the actor's relevance, and the actor's novelty clock
    (FR-ES-03, FR-ES-06)."""
    now = datetime.now(timezone.utc)
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-E2E-2'}) SET c.test_fixture = true, "
            "c.cvss_score = 5.0, c.epss_score = 0.1, c.first_seen = $now "
            "MERGE (a:ThreatActor {merge_key:'apt-e2e'}) "
            "SET a.test_fixture = true, a.first_seen = $now "
            "MERGE (c)-[:EXPLOITED_BY]->(a)",
            now=now,
        ).consume()

    assert _prop(
        driver, "MATCH (a:ThreatActor {merge_key:'apt-e2e'}) RETURN a.relevance_score"
    ) is None

    captured = _capture(lambda: publish_graph_write(
        rel_type="EXPLOITED_BY",
        start_key={"cve_id": "CVE-2026-E2E-2"},
        end_key={"merge_key": "apt-e2e"},
        start_label="CVE", end_label="ThreatActor",
        outcome="created", origin="inferred",
    ))
    handler(captured["event"], None)

    with driver.session() as s:
        row = s.run(
            "MATCH (c:CVE {cve_id:'CVE-2026-E2E-2'}) "
            "MATCH (a:ThreatActor {merge_key:'apt-e2e'}) "
            "RETURN c.severity_adoption AS adoption, a.relevance_score AS rel, "
            "       a.last_significant_event AS lse"
        ).single()
    assert row["adoption"] > 0
    assert row["rel"] is not None
    assert row["lse"] is not None


def test_the_publishers_event_time_is_what_lands_on_the_novelty_clock(driver):
    """`event_time` is minted by the PUBLISHER and must survive to the stamp, so an SNS
    redelivery replays the same instant instead of advancing the clock. A handler that
    ignored the field and called `now()` would still leave a non-null `lse` -- so this
    asserts the VALUE, not merely its presence."""
    minted = datetime(2026, 3, 4, 5, 6, 7, tzinfo=timezone.utc)
    with driver.session() as s:
        s.run(
            "MERGE (a:ThreatActor {merge_key:'apt-e2e-clock'}) SET a.test_fixture = true "
            "MERGE (c:CVE {cve_id:'CVE-2026-E2E-CLK'}) SET c.test_fixture = true "
            "MERGE (c)-[:EXPLOITED_BY]->(a)"
        ).consume()

    captured = _capture(lambda: publish_graph_write(
        rel_type="EXPLOITED_BY",
        start_key={"cve_id": "CVE-2026-E2E-CLK"},
        end_key={"merge_key": "apt-e2e-clock"},
        start_label="CVE", end_label="ThreatActor",
        outcome="created", origin="inferred",
        event_time=minted,
    ))
    assert captured["body"]["event_time"] == minted.isoformat()
    handler(captured["event"], None)

    stamped = _prop(
        driver,
        "MATCH (a:ThreatActor {merge_key:'apt-e2e-clock'}) RETURN a.last_significant_event",
    )
    assert stamped.to_native() == minted


def test_a_matched_outcome_scores_but_does_not_re_spike_the_novelty_clock(driver):
    """The deny-list is a real branch across the boundary: `outcome == 'matched'` means
    no new evidence, so relevance is still recomputed but the clock must not move."""
    with driver.session() as s:
        s.run(
            "MERGE (a:ThreatActor {merge_key:'apt-e2e-matched'}) SET a.test_fixture = true "
            "MERGE (c:CVE {cve_id:'CVE-2026-E2E-M'}) SET c.test_fixture = true "
            "MERGE (c)-[:EXPLOITED_BY]->(a)"
        ).consume()

    captured = _capture(lambda: publish_graph_write(
        rel_type="EXPLOITED_BY",
        start_key={"cve_id": "CVE-2026-E2E-M"},
        end_key={"merge_key": "apt-e2e-matched"},
        start_label="CVE", end_label="ThreatActor",
        outcome="matched", origin="inferred",
    ))
    handler(captured["event"], None)

    assert _prop(
        driver,
        "MATCH (a:ThreatActor {merge_key:'apt-e2e-matched'}) RETURN a.relevance_score",
    ) is not None
    assert _prop(
        driver,
        "MATCH (a:ThreatActor {merge_key:'apt-e2e-matched'}) "
        "RETURN a.last_significant_event",
    ) is None


# --- L2 -> L4: MENTIONS edge_write, via the REAL resolution handler -------------------


def _mock_llm_client():
    """Tier-3 mock that always reports no match, forcing tier 4 (:Provisional creation)
    -- the same shape as tests/nlp/resolution/test_fuzzy.py's `_mock_client`."""
    client = MagicMock()
    block = MagicMock(type="tool_use", input={"matched_merge_key": None})
    response = MagicMock()
    response.content = [block]
    client.messages.create.return_value = response
    return client


def test_a_mentions_write_from_the_real_resolution_handler_refines_node_confidence(
    driver, monkeypatch
):
    """MENTIONS is the highest-volume message in the pipeline and the only driver of
    FR-ES-08 (node confidence, the one L4 score that ACCUMULATES). Every other MENTIONS
    test in this codebase hand-builds the SNS message; this one drives the REAL
    `src.nlp.resolution.handler._process_article` -- the actual L2 publisher -- and feeds
    its REAL captured message into the REAL L4 handler, so a drift in the endpoint key
    shape, the label, or the outcome vocabulary between the two ends is not invisible."""
    monkeypatch.setenv(
        "CROSSROADS_RESOLVED_ARTICLES_QUEUE_URL", "https://sqs.example/resolved-articles"
    )
    article_id = "e2e-mentions-src::e2e-mentions-guid"
    with driver.session() as s:
        s.run(
            "MERGE (a:Article {source_guid_key: $key}) SET a.test_fixture = true "
            "MERGE (src:Source {source_id: 'e2e-mentions-src'}) "
            "SET src.test_fixture = true, src.credibility_score = 0.8 "
            "MERGE (a)-[:PUBLISHED_BY]->(src)",
            key=article_id,
        ).consume()

    message = {
        "article_id": article_id,
        "mentions": [{
            "article_id": article_id,
            "entity_type": "threat_actor",
            "surface_text": "E2E Mentions Actor",
            "char_span": [0, 19],
            "extraction_confidence": 0.5,
            "context_snippet": "...E2E Mentions Actor...",
        }],
    }
    merge_key = "e2e mentions actor"

    sns = MagicMock()
    with patch("boto3.client", return_value=sns):
        _process_article(message, MagicMock(), driver, _mock_llm_client)
    _flag_fixture(driver, merge_key)

    confidence_before = _prop(
        driver, "MATCH (n:ThreatActor {merge_key:$k}) RETURN n.confidence", k=merge_key
    )
    # `_create_provisional` seeds confidence at min(extraction_confidence, 0.99) = 0.5;
    # the MENTIONS write's own contribution (credibility 0.8 * extraction_confidence 0.5
    # = 0.4) must still move it, so this is not a vacuous before/after pair.
    assert confidence_before == pytest.approx(0.5)

    call = sns.publish.call_args
    event = {"Records": [{"Sns": {"Message": call.kwargs["Message"]}}]}
    handler(event, None)

    confidence_after = _prop(
        driver, "MATCH (n:ThreatActor {merge_key:$k}) RETURN n.confidence", k=merge_key
    )
    assert confidence_after == pytest.approx(0.4)


# --- The typed-topic contract ---------------------------------------------------------


def test_every_publisher_stamps_a_type_the_scoring_subscription_accepts(topic_env):
    """Binds the two publishers to the ScoringStack filter policy's allowlist.

    The allowlist itself is pinned against the SYNTHESIZED template in
    tests/infra/test_scoring_stack.py; this end holds the publishers to the same two
    literals. If a publisher's `message_type` drifts, its messages are dropped by the
    filter policy in production -- silently, with no error, no DLQ and no log.
    """
    accepted = {"edge_write", "node_write"}
    for publish_call, expected in (
        (lambda: publish_node_write(label="CVE", key={"cve_id": "X"},
                                    changed_fields=["cvss_score"]), MESSAGE_TYPE_NODE_WRITE),
        (lambda: publish_graph_write(rel_type="USES", start_key={"merge_key": "a"},
                                     end_key={"technique_id": "T1"},
                                     outcome="created"), MESSAGE_TYPE_EDGE_WRITE),
    ):
        captured = _capture(publish_call)
        assert captured["attributes"]["message_type"]["StringValue"] == expected
        # Body copy too: the Lambda dispatches on the body, not the attribute.
        assert captured["body"]["message_type"] == expected
        assert expected in accepted


def test_publish_node_write_rejects_a_bare_string_changed_fields(topic_env):
    """A bare string is iterable BY CHARACTER, so L4's
    `frozenset.intersection("cvss_score")` is empty and severity silently never
    recomputes. The publisher must refuse rather than emit a message that does nothing."""
    with pytest.raises(TypeError, match="changed_fields"):
        _capture(lambda: publish_node_write(
            label="CVE", key={"cve_id": "X"}, changed_fields="cvss_score",
        ))


def test_publish_node_write_accepts_a_set_and_emits_it_as_a_json_list(topic_env):
    """A set is a legitimate `changed_fields` -- callers build one by diffing properties --
    but it is not JSON-serializable, so the publisher must coerce it. Without the
    coercion this raises TypeError at `json.dumps` and the announcement is lost."""
    captured = _capture(lambda: publish_node_write(
        label="CVE", key={"cve_id": "X"}, changed_fields={"cvss_score"},
    ))
    assert captured["body"]["changed_fields"] == ["cvss_score"]


# --- L2 -> L4 through the GRAPH: FR-ES-10's node half ---------------------------------


def test_a_provisional_node_created_by_l2_is_prunable_by_l4(driver):
    """FR-ES-10 (node half), end to end across the L2/L4 boundary that is NOT a message.

    L4's node-prune predicate reads `first_seen`, and L2's resolver is the only thing that
    creates `:Provisional` nodes. Until this landed, nothing wrote the property, so the
    predicate matched nothing and the requirement was INERT in production while every
    unit test of the scan passed happily against hand-seeded nodes.

    So this seeds via the REAL `_create_provisional` and reads via the REAL
    `flag_pruning_batch`, with no hand-written `first_seen` anywhere in between.
    """
    mention = RawMention(
        article_id="e2e-src::e2e-guid",
        entity_type="threat_actor",
        surface_text="Provisional E2E Actor",
        char_span=(0, 21),
        extraction_confidence=0.1,  # below prune_confidence_floor (0.2)
        context_snippet="an e2e context snippet",
    )
    _seed_article(driver, mention.article_id)
    key = _create_provisional(driver, mention, "ThreatActor", "provisional e2e actor")
    _flag_fixture(driver, key)

    stored = _prop(
        driver, "MATCH (n:ThreatActor {merge_key:$k}) RETURN n.first_seen", k=key
    )
    assert stored is not None, "L2 must stamp first_seen or FR-ES-10's node half is inert"

    knobs = ConfidenceKnobs.from_config()
    # A quarter past the staleness threshold -- the node is old and low-confidence.
    later = datetime.now(timezone.utc) + timedelta(days=knobs.prune_stale_days + 1)
    with driver.session() as s:
        s.execute_write(lambda tx: flag_pruning_batch(
            tx, cursor=None, batch_size=100, knobs=knobs, now=later, target="nodes",
        ))

    assert _prop(
        driver, "MATCH (n:ThreatActor {merge_key:$k}) RETURN n.prune_candidate", k=key
    ) is True
    assert _prop(
        driver, "MATCH (n:ThreatActor {merge_key:$k}) RETURN n.prune_reason", k=key
    ) == "stale_low_confidence_provisional"


def test_a_freshly_created_provisional_node_is_not_prunable(driver):
    """The other side of the same predicate: `first_seen` must be a real creation clock,
    not a constant. A node created today is low-confidence but NOT stale, so the scan
    must clear its flag rather than set it."""
    mention = RawMention(
        article_id="e2e-src::e2e-guid-2",
        entity_type="threat_actor",
        surface_text="Fresh E2E Actor",
        char_span=(0, 15),
        extraction_confidence=0.1,
        context_snippet="another e2e context snippet",
    )
    _seed_article(driver, mention.article_id)
    key = _create_provisional(driver, mention, "ThreatActor", "fresh e2e actor")
    _flag_fixture(driver, key)

    knobs = ConfidenceKnobs.from_config()
    with driver.session() as s:
        s.execute_write(lambda tx: flag_pruning_batch(
            tx, cursor=None, batch_size=100, knobs=knobs,
            now=datetime.now(timezone.utc), target="nodes",
        ))

    assert _prop(
        driver, "MATCH (n:ThreatActor {merge_key:$k}) RETURN n.prune_candidate", k=key
    ) is False
