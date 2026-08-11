"""Relevance scoring for a single entity (FR-ES-02, FR-ES-06).

Objective relevance only. Per-user ranking ("relevant to MY stack") is L7 Delivery's job,
layered on top of this score.

No lock: a pure recompute of current timestamps, mentioning sources and current degree.
"""

from datetime import date, datetime, time, timezone

from neo4j import ManagedTransaction

from src.common.graph.edge_types import ASSERTION_EDGE_TYPES
from src.common.graph.writer import _check_identifier
from src.scoring._shared import SCORED_LABELS, resolve_key_prop
from src.scoring.formulas import RelevanceResult, relevance
from src.scoring.knobs import RelevanceKnobs

# `type(r) IN $assertion_types` is a PARAMETER, not interpolation -- relationship types
# can be parameterized in a WHERE predicate even though they cannot in a pattern. The
# direction is undirected (`-[r]-`) because centrality is about connectedness: an actor
# with inbound ATTRIBUTED_TO edges is as connected as one with outbound USES edges.
_READ = """
MATCH (n:{label} {{{key_prop}: $key}})
OPTIONAL MATCH (a:Article)-[:MENTIONS]->(n)
OPTIONAL MATCH (a)-[:PUBLISHED_BY]->(s:Source)
WITH n, max(s.credibility_score) AS credibility
OPTIONAL MATCH (n)-[r]-()
WHERE type(r) IN $assertion_types
RETURN coalesce(credibility, 0.0) AS credibility,
       count(DISTINCT r)          AS assertion_degree,
       coalesce(n.last_significant_event, n.first_seen) AS clock
"""

_WRITE = "MATCH (n:{label} {{{key_prop}: $key}}) SET n.relevance_score = $score"


# An unusable clock means OLDEST, never newest: novelty floors at 0 (0.5 ** inf), so an
# entity we cannot date sinks below any entity we can. The inverse default -- age 0, i.e.
# maximum novelty -- would put every untimestamped node above a genuinely new one, and
# `first_seen` coverage is still PARTIAL: L2's resolver stamps it on the :Provisional nodes
# it creates (Task 5.3) and abuse.ch stamps it on IOCs (Task 3.5), but nothing writes it on
# a canonical CVE/ThreatActor/MalwareFamily/Campaign, so "untimestamped" is most of the
# graph on first deploy rather than an edge case.
_UNUSABLE_CLOCK_AGE_DAYS = float("inf")


def _age_days(clock, now: datetime) -> float:
    """Days from the entity's most recent significant event to `now`.

    Deliberately total: it returns a number for ANY input rather than raising. The daily
    novelty sweep scans a whole label in one transaction, so a single raise rolls the
    batch back and the cursor never advances -- the sweep would never terminate, taking
    down the safety net that the no-lock design elsewhere in this package relies on.

    Values seen in practice: neo4j DateTime/Date (`.to_native()`), a plain datetime, a
    plain date (Neo4j `date`, which carries no time or zone), None, and a plain STRING --
    e.g. a legacy node written before an L1 writer's temporal properties were normalized,
    or any other source that reaches this function without going through a normalizer.
    This function stays reader-agnostic and total rather than assuming every writer gets
    it right: such a node simply scores as undatable.
    """
    dt = clock.to_native() if hasattr(clock, "to_native") else clock
    if isinstance(dt, datetime):
        pass
    elif isinstance(dt, date):
        # datetime is a subclass of date, so this arm is reached only by a true date.
        dt = datetime.combine(dt, time.min)
    else:
        return _UNUSABLE_CLOCK_AGE_DAYS
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt).total_seconds() / 86400.0


def score_entity(
    tx: ManagedTransaction,
    *,
    label: str,
    key: str,
    knobs: RelevanceKnobs,
    now: datetime,
) -> RelevanceResult | None:
    """Recompute and store one entity's relevance. Returns None if it does not exist.

    `now` MUST be timezone-aware. Unlike the stored clock -- which arrives from the graph
    and may be anything -- `now` is supplied by our own callers, so a naive value is a
    caller bug worth surfacing as the TypeError it causes rather than silently assuming a
    zone. Both production callers pass `datetime.now(timezone.utc)`.
    """
    # resolve_key_prop validates BOTH the label and the key property, which are BOTH
    # interpolated into the Cypher below. Do not re-derive this inline: an earlier draft
    # of this task did `_check_identifier(label)` + a raw dict lookup, leaving key_prop
    # unvalidated -- the exact hole resolve_key_prop exists to close.
    key_prop = resolve_key_prop(label)
    # SCORED_LABELS is the authority on what carries a relevance_score; KEY_PROP_BY_LABEL
    # is a general-purpose map that could grow entries (Article, Source) which must NEVER
    # be scored. They are identical today, so resolve_key_prop alone would appear to
    # suffice -- but then adding one row to that map silently starts writing
    # relevance_score onto Articles. Order matters: resolve_key_prop runs FIRST so the
    # identifier validation stays load-bearing on a hostile label.
    if key_prop is None or label not in SCORED_LABELS:
        raise ValueError(f"label {label!r} carries no relevance_score (see _shared.py)")

    row = tx.run(
        _READ.format(label=label, key_prop=key_prop),
        key=key,
        assertion_types=list(ASSERTION_EDGE_TYPES),
    ).single()
    if row is None:
        return None

    result = relevance(
        age_days=_age_days(row["clock"], now),
        credibility=row["credibility"],
        assertion_degree=row["assertion_degree"],
        knobs=knobs,
    )
    tx.run(
        _WRITE.format(label=label, key_prop=key_prop), key=key, score=result.score
    ).consume()
    return result


# Returns labels(n) so the label is resolved from the scan row itself -- no second
# query per node, unlike event_handler._resolve_endpoint which only has a key dict.
#
# The label union is INTERPOLATED, not parameterized -- Cypher label patterns cannot take
# a parameter -- so every label goes through _check_identifier first, per this package's
# no-exceptions rule (see resolve_key_prop). This is what turns the plan from an
# AllNodesScan (scanning every node in the graph, including :Article, the highest-count
# label, on every page) into a UnionNodeByLabelsScan (verified with EXPLAIN against a live
# 6.2 instance) -- `MATCH (n) WHERE any(l IN labels(n) WHERE l IN $scored_labels)` cannot
# use a label index no matter how the WHERE clause is phrased.
_SCORED_LABEL_UNION = "|".join(_check_identifier(label, "label") for label in SCORED_LABELS)
_NOVELTY_SCAN = f"""
MATCH (n:{_SCORED_LABEL_UNION})
WHERE ($cursor IS NULL OR elementId(n) > $cursor)
WITH n ORDER BY elementId(n) LIMIT $batch_size
RETURN elementId(n) AS eid, labels(n) AS labels, n AS node
"""


def _label_of(labels: list[str]) -> str | None:
    """Pick the scored label from a node's label list.

    SCORED_LABELS is ordered, and a node carrying two of them would be a schema bug;
    first match wins deterministically. `:Provisional` is a secondary label and is never
    in SCORED_LABELS, so it cannot be selected here.
    """
    for label in SCORED_LABELS:
        if label in labels:
            return label
    return None


def rescan_novelty_batch(
    tx: ManagedTransaction,
    *,
    cursor: str | None,
    batch_size: int,
    knobs: RelevanceKnobs,
    now: datetime,
) -> tuple[int, str | None]:
    """Recompute relevance for one page of scored entities (FR-ES-07).

    Novelty decays with time alone, so this must run even on a day with zero events.
    Returns (count, next cursor); a None cursor means the scan is exhausted.
    """
    rows = list(
        tx.run(
            _NOVELTY_SCAN,
            cursor=cursor,
            batch_size=batch_size,
        )
    )
    if not rows:
        return 0, None

    scored = 0
    for row in rows:
        label = _label_of(row["labels"])
        if label is None:
            continue
        # resolve_key_prop, NOT a raw KEY_PROP_BY_LABEL lookup -- the single validated
        # path. A label outside the map returns None here instead of raising KeyError
        # and killing the whole page's transaction.
        key_prop = resolve_key_prop(label)
        if key_prop is None:
            continue
        key = row["node"].get(key_prop)
        if key is None:
            continue
        score_entity(tx, label=label, key=key, knobs=knobs, now=now)
        scored += 1
    # The cursor advances past every row READ, not every row scored: a node skipped for
    # a missing key must not be re-read forever, or the sweep never terminates.
    return scored, rows[-1]["eid"]
