"""graph-writes SNS consumer: the targeted, low-latency recompute path (FR-ES-03).

This is an OPTIMIZATION, not the correctness guarantee. The daily sweep
(sweep_handler.py) recomputes unconditionally, so a dropped, filtered-out, or failed
event costs freshness only -- never correctness. That is what lets this handler skip
aggressively.

That guarantee covers node confidence only because the sweep's `confidence_rescan` phase
exists. Severity, relevance and edge decay are pure recomputes and repair themselves;
confidence ACCUMULATES, so a lost MENTIONS event would otherwise drop that story
cluster's contribution permanently, with nothing to notice. Remove that phase and this
paragraph becomes false.

What it swallows is narrow and deliberate: unknown `message_type` VALUES become a skip.
Malformed records (bad JSON, a non-object Message, an SQS-shaped record) still raise --
one record per invocation, two async retries, then the DLQ. A blanket `except Exception`
here would also swallow a Neo4j outage and rob the DLQ of its signal.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any

from src.common.graph.edge_types import ASSERTION_EDGE_TYPES
from src.common.graph.publish import MESSAGE_TYPE_EDGE_WRITE, MESSAGE_TYPE_NODE_WRITE
from src.common.neo4j_driver import get_driver
from src.scoring._shared import KEY_PROP_BY_LABEL, SCORED_LABELS
from src.scoring.confidence import refine_from_mention
from src.scoring.knobs import RelevanceKnobs, SeverityKnobs
from src.scoring.relevance import score_entity
from src.scoring.severity import score_cve
from src.scoring.significance import stamp_significant_event

logger = logging.getLogger(__name__)

# `merge_key` is shared by more than one label, so it alone needs a graph lookup. DERIVED,
# not hand-listed: a fourth merge_key label added to _shared must not silently fail to
# register here.
_MERGE_KEY_LABELS = tuple(
    label for label in SCORED_LABELS if KEY_PROP_BY_LABEL[label] == "merge_key"
)

# Constrained to those labels rather than a bare `MATCH (n {merge_key: $key})`. Two
# reasons, both load-bearing:
#  1. `merge_key` is a lowercased normalized NAME and its UNIQUE constraints are PER-LABEL,
#     so a ThreatActor and a MalwareFamily can both legitimately hold 'lazarus' -- an
#     ordinary naming pattern in threat intel, not a contrived case. An unlabelled match
#     returns both and `.single()` would pick one arbitrarily by creation order.
#  2. An unlabelled match cannot use any index: it is an AllNodesScan of the entire graph,
#     run on every MENTIONS write -- the highest-volume message in the pipeline.
_RESOLVE_MERGE_KEY = (
    "MATCH (n:" + "|".join(_MERGE_KEY_LABELS) + " {merge_key: $key}) "
    "RETURN labels(n) AS labels"
)

# A change to any of these moves severity; anything else on a CVE does not.
# `epss_score` has no publisher on purpose: EPSS refreshes ~200k CVEs daily, so it is
# sweep-only by design (design spec §4, plan Task 1.2) rather than 200k SNS publishes.
# The entry stays because it costs nothing and is correct if that ever changes.
_SEVERITY_INPUT_FIELDS = frozenset({"cvss_score", "epss_score", "exploited_in_wild"})


def _handle_node_write(message: dict, driver, severity_knobs: SeverityKnobs) -> bool:
    if message.get("label") != "CVE":
        return False
    if not _SEVERITY_INPUT_FIELDS.intersection(message.get("changed_fields") or []):
        return False
    cve_id = (message.get("key") or {}).get("cve_id")
    if not cve_id:
        return False
    with driver.session() as session:
        session.execute_write(
            lambda tx: score_cve(tx, cve_id=cve_id, knobs=severity_knobs)
        )
    return True


def _resolve_endpoint(tx, endpoint_key: dict, label: str | None = None) -> tuple[str, str] | None:
    """Map a graph-writes endpoint key dict to (label, key), or None if undecidable.

    `label` is the message's own `start_label`/`end_label` and is PREFERRED when present:
    the publisher knows the label for certain, so trusting it removes the ambiguity below
    entirely. It is still checked against SCORED_LABELS and against the key property the
    label actually uses -- a label naming an unscored node, or one inconsistent with the
    key, resolves to nothing rather than to a guess.

    When the label is absent -- an in-flight message published before the field existed --
    this falls back to the original behaviour: `merge_key` is shared by several labels, so
    that case asks the graph which label the node carries, and declines when more than one
    answers. Keeping the fallback is what makes the new fields purely additive.
    """
    if not endpoint_key or len(endpoint_key) != 1:
        return None
    ((prop, value),) = endpoint_key.items()

    if label is not None:
        if label in SCORED_LABELS and KEY_PROP_BY_LABEL[label] == prop:
            return label, value
        return None

    if prop != "merge_key":
        for label in SCORED_LABELS:
            if KEY_PROP_BY_LABEL[label] == prop:
                return label, value
        return None

    matched = {
        label
        for record in tx.run(_RESOLVE_MERGE_KEY, key=value)
        for label in record["labels"]
        if label in _MERGE_KEY_LABELS
    }
    if len(matched) == 1:
        return matched.pop(), value

    # Zero matches: an unknown or unscored node -- nothing to do.
    # More than one: the message names an endpoint by key ALONE, and two different
    # entities answer to that key. L4 genuinely cannot tell which one the edge touched,
    # so it declines rather than guessing. Skipping costs one entity a novelty spike;
    # guessing wrong affirmatively spikes an entity that had no news, and the daily sweep
    # cannot repair that (it recomputes relevance but never writes last_significant_event).
    # Only reachable for a message published before `start_label`/`end_label` existed;
    # a labelled message never gets here.
    if matched:
        logger.warning(
            "ambiguous merge_key %r matches %s; skipping rather than guessing",
            value,
            sorted(matched),
        )
    return None


def _event_time(message: dict) -> datetime:
    """The event's OWN timestamp, so a redelivery replays the same instant.

    Falls back to now() only when the message predates the field, or carries a value that
    cannot be used: `stamp_significant_event` rejects a naive datetime outright, and a
    naive value here would otherwise take down the whole record.
    """
    raw = message.get("event_time")
    if not raw:
        return datetime.now(timezone.utc)
    try:
        parsed = datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        logger.warning("unparseable event_time %r; falling back to now()", raw)
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        logger.warning("naive event_time %r; falling back to now()", raw)
        return datetime.now(timezone.utc)
    return parsed


def _is_newsworthy(message: dict) -> bool:
    """Whether this write should re-spike the novelty clock (FR-ES-06).

    A DENY-list on `matched`, deliberately, NOT an allow-list on `created`. `outcome` is
    not a uniform vocabulary across producers: L2 resolution publishes a
    `resolution_status` (`resolved`|`provisional`), L1 publishes `created`|`matched`, and
    L2 inference publishes `created`|`updated`|`matched`. An allow-list on `created` would
    therefore stamp NOTHING on the MENTIONS path -- the highest-volume path in the
    pipeline -- so the only safe reading is that everything is news EXCEPT the one value
    that positively means "already folded in".

    A message with no `outcome` at all predates the field and is treated as news, which
    is the pre-existing behaviour.
    """
    return message.get("outcome") != "matched"


def _refine_mention(tx, endpoint_key, article_key, label=None) -> bool:
    """Apply this mention's noisy-OR contribution to the mentioned node (FR-ES-08).

    Its own transaction rather than a step inside _score_endpoint: this is the one write
    in L4 that holds a node lock, and folding it in would hold that lock across
    score_entity's degree/credibility queries -- widening contention on exactly the
    hottest message in the pipeline for no benefit (relevance does not read confidence).

    Returns True only if a contribution was actually applied, so a mention of a canonical
    (non-provisional) node does not masquerade as refinement work.
    """
    if not article_key:
        return False
    resolved = _resolve_endpoint(tx, endpoint_key, label)
    if resolved is None:
        return False
    resolved_label, key = resolved
    return (
        refine_from_mention(tx, label=resolved_label, key=key, article_key=article_key)
        is not None
    )


def _score_endpoint(
    tx, endpoint_key, relevance_knobs: RelevanceKnobs, now, label=None, stamp=True
) -> bool:
    """Re-score an endpoint, stamping the novelty clock only when `stamp`.

    `stamp` is the caller's newsworthiness verdict (see `_is_newsworthy`). Scoring still
    happens either way: a re-emitted edge can carry no news and STILL have moved the
    entity's degree or credibility, so skipping the stamp must not also skip the score.
    """
    resolved = _resolve_endpoint(tx, endpoint_key, label)
    if resolved is None:
        return False
    resolved_label, key = resolved
    # Stamp BEFORE scoring: score_entity reads last_significant_event, so scoring first
    # would compute novelty against the pre-event clock and store a stale value until
    # the next sweep.
    if stamp:
        stamp_significant_event(tx, label=resolved_label, key=key, at=now)
    return (
        score_entity(tx, label=resolved_label, key=key, knobs=relevance_knobs, now=now)
        is not None
    )


def _handle_edge_write(
    message: dict,
    driver,
    severity_knobs: SeverityKnobs,
    relevance_knobs: RelevanceKnobs,
) -> bool:
    rel_type = message.get("rel_type")
    # The event's OWN instant, not this delivery's, so an SNS redelivery replays the
    # same clock instead of advancing it.
    now = _event_time(message)
    stamp = _is_newsworthy(message)
    did = False

    with driver.session() as session:
        if rel_type == "MENTIONS":
            # New evidence: credibility may rise and the novelty clock re-spikes.
            # Only the END endpoint is an entity; the start is an Article.
            article_key = (message.get("start_key") or {}).get("source_guid_key")
            end_label = message.get("end_label")
            did = session.execute_write(
                _refine_mention, message.get("end_key"), article_key, end_label
            )
            did |= session.execute_write(
                _score_endpoint, message.get("end_key"), relevance_knobs, now,
                end_label, stamp,
            )
        elif rel_type in ASSERTION_EDGE_TYPES:
            # Centrality moved at BOTH ends.
            for which, which_label in (("start_key", "start_label"), ("end_key", "end_label")):
                did |= session.execute_write(
                    _score_endpoint, message.get(which), relevance_knobs, now,
                    message.get(which_label), stamp,
                )
            # EXPLOITED_BY is CVE->{ThreatActor,MalwareFamily,Campaign}, so the CVE is
            # always the START endpoint (technical-specification.md §3.2).
            if rel_type == "EXPLOITED_BY":
                cve_id = (message.get("start_key") or {}).get("cve_id")
                if cve_id:
                    session.execute_write(
                        lambda tx: score_cve(tx, cve_id=cve_id, knobs=severity_knobs)
                    )
                    did = True
    return did


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    driver = get_driver()
    severity_knobs = SeverityKnobs.from_config()
    relevance_knobs = RelevanceKnobs.from_config()

    processed = 0
    skipped = 0
    for record in event.get("Records", []):
        message = json.loads(record["Sns"]["Message"])
        message_type = message.get("message_type")

        if message_type == MESSAGE_TYPE_NODE_WRITE:
            did = _handle_node_write(message, driver, severity_knobs)
        elif message_type == MESSAGE_TYPE_EDGE_WRITE:
            did = _handle_edge_write(
                message, driver, severity_knobs, relevance_knobs
            )
        else:
            did = False

        processed += int(did)
        skipped += int(not did)

    return {"processed": processed, "skipped": skipped}
