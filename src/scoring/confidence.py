"""Confidence refinement (FR-ES-08) and edge temporal decay (FR-ES-09).

These two are opposites in a way that matters:

  * Node refinement ACCUMULATES (noisy-OR across corroborating stories), so it is a
    read-modify-write and MUST hold a lock. L3's per-task review proved the unlocked
    version loses 9 of 10 concurrent contributions, deterministically.
  * Edge decay RECOMPUTES from an immutable base plus a timestamp, so it needs no lock
    and is trivially idempotent.
"""

from datetime import datetime, timezone

from neo4j import ManagedTransaction

from src.scoring._shared import resolve_key_prop
from src.scoring.formulas import clamp01, effective_confidence, noisy_or
from src.scoring.knobs import ConfidenceKnobs

# The lock is held to end of transaction, so the read below and the SET that follows
# serialize against any concurrent refiner. `:Provisional` is in the MATCH itself, which
# is what keeps canonical nodes at confidence = 1.0 by construction rather than by an
# explicit guard someone could later delete.
#
# The node is matched TWICE on purpose. Projecting `n.confidence` off the same cursor
# that fed apoc.lock.nodes returns the value that cursor already saw -- i.e. the
# PRE-lock state -- so the lock buys nothing and 9 of 10 concurrent contributions are
# still lost (measured: 1 cluster id of 10, identical to the unlocked query). Only a
# pattern match issued AFTER the lock reads the freshly committed state. This is the
# same shape as src/common/graph/assertion_edges.py::_existing, where the data actually
# read -- the OPTIONAL MATCH for the relationship -- is likewise matched after the lock.
_READ = """
MATCH (locked:{label}:Provisional {{{key_prop}: $key}})
CALL apoc.lock.nodes([locked])
WITH locked
MATCH (n:{label}:Provisional {{{key_prop}: $key}})
RETURN coalesce(n.confidence, 0.0) AS confidence,
       coalesce(n.contributing_story_cluster_ids, []) AS clusters,
       coalesce(n.contributing_story_cluster_scores, []) AS scores
"""

# The two lists are PARALLEL and are always written together in one SET, so index i of
# one always describes index i of the other. Neo4j cannot store a map as a node property,
# only primitives and arrays of primitives, which is why this is two lists and not one
# dict.
_WRITE = """
MATCH (n:{label}:Provisional {{{key_prop}: $key}})
SET n.confidence = $confidence,
    n.contributing_story_cluster_ids = $clusters,
    n.contributing_story_cluster_scores = $scores
"""

# NOTE the doubled braces on `source_guid_key`: this string goes through .format(), so
# every literal Cypher map brace must be escaped or format() reads it as a field name
# and raises KeyError. Same rule applies to every .format()ed query in this package.
_MENTION_CONTEXT = """
MATCH (a:Article {{source_guid_key: $article_key}})-[m:MENTIONS]->
      (n:{label}:Provisional {{{key_prop}: $key}})
OPTIONAL MATCH (a)-[:PUBLISHED_BY]->(s:Source)
RETURN coalesce(s.credibility_score, 0.0)  AS credibility,
       coalesce(m.extraction_confidence, 0.0) AS extraction_confidence,
       coalesce(a.story_cluster_id, a.source_guid_key) AS cluster
"""


def refine_provisional_confidence(
    tx: ManagedTransaction,
    *,
    label: str,
    key: str,
    story_cluster_id: str,
    contribution: float,
) -> float | None:
    """Apply one story cluster's contribution to a provisional node.

    Returns the new confidence, or None if the node is absent or already canonical.

    Confidence is RECOMPUTED from the full stored set of per-cluster contributions, not
    accumulated incrementally. Design spec §5.3 defines `s_j` as the MAX over that
    cluster's mentioning articles, and an incremental form cannot express that: it takes
    whichever contribution arrives FIRST and can never raise it, so a low-credibility blog
    that happens to be delivered before a top-tier vendor report in the SAME cluster pins
    that cluster low forever. Worse, SNS delivery order is nondeterministic, so identical
    data could settle on different confidences. Recomputing from the stored set makes the
    result depend only on WHICH (cluster, contribution) pairs have been seen, never on the
    order they arrived in.

    `contributing_story_cluster_ids` is deliberately UNCAPPED, for the same reason
    technical-specification.md §3.2 gives for the edge property: this list IS the
    idempotency check, so evicting an id would make a re-emitted cluster read as new,
    re-fire the noisy-OR, and inflate confidence -- destroying the very no-op guarantee
    the field exists to provide.
    """
    # resolve_key_prop validates BOTH the label and the key property, and BOTH are
    # interpolated into the Cypher below. Do NOT re-derive this inline as
    # `_check_identifier(label)` + a raw dict lookup -- that leaves key_prop unvalidated,
    # which is the exact hole resolve_key_prop exists to close.
    key_prop = resolve_key_prop(label)
    if key_prop is None:
        return None

    row = tx.run(_READ.format(label=label, key_prop=key_prop), key=key).single()
    if row is None:
        return None

    # The two lists are written together in one SET and are meaningless apart, so a length
    # mismatch means something outside this module rewrote one of them. Refusing is the
    # only honest option: silently padding would invent per-cluster contributions that were
    # never observed and bake them into every future recompute.
    stored_ids, stored_scores = list(row["clusters"]), list(row["scores"])
    if len(stored_ids) != len(stored_scores):
        raise ValueError(
            f"{label} {key!r} has {len(stored_ids)} cluster ids but "
            f"{len(stored_scores)} scores; the parallel lists are corrupt"
        )

    contribution = clamp01(contribution)
    by_cluster = dict(zip(stored_ids, stored_scores))
    prior = by_cluster.get(story_cluster_id)
    # `<=`, not `!=`: re-delivering the same contribution is the idempotent no-op, and a
    # LOWER one from a weaker article in an already-counted cluster must not pull the
    # cluster's max down.
    if prior is not None and contribution <= prior:
        return row["confidence"]

    by_cluster[story_cluster_id] = contribution
    clusters = sorted(by_cluster)
    scores = [by_cluster[c] for c in clusters]
    confidence = noisy_or(scores)

    tx.run(
        _WRITE.format(label=label, key_prop=key_prop),
        key=key,
        confidence=confidence,
        clusters=clusters,
        scores=scores,
    ).consume()
    return confidence


def refine_from_mention(
    tx: ManagedTransaction, *, label: str, key: str, article_key: str
) -> float | None:
    """Resolve one mention's contribution and apply it. None if not provisional.

    `coalesce(a.story_cluster_id, a.source_guid_key)`: an article not yet deduped has no
    cluster id. Falling back to its own id keeps each such article a distinct
    contributor -- without it, every un-clustered article collapses into a single `null`
    bucket and only the first one ever counts.
    """
    # Same rule as refine_provisional_confidence: one validated interpolation path.
    key_prop = resolve_key_prop(label)
    if key_prop is None:
        return None
    row = tx.run(
        _MENTION_CONTEXT.format(label=label, key_prop=key_prop),
        article_key=article_key,
        key=key,
    ).single()
    if row is None:
        return None
    return refine_provisional_confidence(
        tx,
        label=label,
        key=key,
        story_cluster_id=row["cluster"],
        contribution=row["credibility"] * row["extraction_confidence"],
    )


# Cursor pagination on elementId, NOT SKIP/LIMIT: SKIP over a set being concurrently
# modified can skip or repeat rows. elementId ordering is stable and total.
_DECAY_SCAN = """
MATCH ()-[r]->()
WHERE r.inferred_confidence IS NOT NULL
  AND ($cursor IS NULL OR elementId(r) > $cursor)
WITH r ORDER BY elementId(r) LIMIT $batch_size
RETURN elementId(r)                              AS rid,
       r.inferred_confidence                     AS inferred,
       coalesce(r.authoritative_confidence, 0.0) AS authoritative,
       r.last_confirmed                          AS last_confirmed
"""

_DECAY_WRITE = """
MATCH ()-[r]->() WHERE elementId(r) IN keys($by_id)
SET r.confidence = $by_id[elementId(r)]
"""


def _days_since(last_confirmed, now: datetime) -> float | None:
    if last_confirmed is None:
        return None
    dt = (
        last_confirmed.to_native()
        if hasattr(last_confirmed, "to_native")
        else last_confirmed
    )
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt).total_seconds() / 86400.0


def decay_edges_batch(
    tx: ManagedTransaction,
    *,
    cursor: str | None,
    batch_size: int,
    halflife_days: float,
    now: datetime,
) -> tuple[list[str], str | None]:
    """Recompute effective confidence for one page of inferred edges (FR-ES-09).

    Writes only `confidence`. `inferred_confidence` -- the noisy-OR base Inference owns --
    is read and never touched, which is exactly why re-running is a no-op.

    Returns (touched edge ids, next cursor). A None cursor means the scan is exhausted.
    """
    rows = list(tx.run(_DECAY_SCAN, cursor=cursor, batch_size=batch_size))
    if not rows:
        return [], None

    by_id = {
        row["rid"]: effective_confidence(
            authoritative_confidence=row["authoritative"],
            inferred_confidence=row["inferred"],
            days_since_last_confirmed=_days_since(row["last_confirmed"], now),
            halflife_days=halflife_days,
        )
        for row in rows
    }
    tx.run(_DECAY_WRITE, by_id=by_id).consume()
    return list(by_id), rows[-1]["rid"]


# The scan ONLY chooses the page. It deliberately reads no evidence: a value decided
# here would be decided before any lock is taken, and a refinement committing between
# this statement and the write below would then be clobbered by a write that holds the
# lock the whole time. Locking serialises writers against each other; it does nothing
# about a writer that already made up its mind.
_CONFIDENCE_SCAN = """
MATCH (n:Provisional)
WHERE $cursor IS NULL OR elementId(n) > $cursor
WITH n ORDER BY elementId(n) LIMIT $batch_size
RETURN elementId(n) AS eid
"""

# Lock, then rebuild AND write in one statement -- the deciding read is inside the lock.
#
# Evidence is rebuilt from the graph rather than from the node's own parallel lists:
# those lists are what may be lost or corrupt, so a repair that trusted them would repair
# nothing.
#
# Same lock-then-re-MATCH shape as _READ: projecting off the binding that fed
# apoc.lock.nodes returns the PRE-lock state. Keyed on elementId, so no label or key
# property is interpolated and nothing here needs resolve_key_prop. `:Provisional` is
# re-asserted after the lock, so a node promoted to canonical between the scan and the
# lock keeps its confidence.
#
# The OPTIONAL MATCHes must stay optional, and the null cluster must be filtered AFTER
# the collect, never in a WHERE before it. A `WHERE cluster IS NOT NULL` earlier drops
# the whole row, so a node whose last MENTIONS edge was retracted would silently keep its
# stale confidence instead of falling to zero -- the one case this phase exists to
# notice. Filtering the collected list leaves an empty list, and the noisy-OR of nothing
# is 0.0.
#
# `1 - product(1 - s)` is formulas.noisy_or, and each CASE is formulas.clamp01; they are
# expressed in Cypher only so the read cannot escape the lock. Both agree to the bit on
# the values this pipeline produces (pinned by the "no-op when every event landed" test).
#
# The PER-ELEMENT clamp is the load-bearing one and is pinned by a test: an out-of-range
# credibility_score reaches here unchecked (config/sources.yaml documents the [0, 1] bound
# in a COMMENT, and source_config._load_config validates only that the field is present),
# and without it a confidence of 1.75 is stored -- off the scale the whole layer is
# defined on, silently changing the meaning of every downstream `confidence < x`.
#
# The clamp on `combined` is UNREACHABLE while that per-element clamp stands, since a
# noisy-OR over [0, 1] is itself in [0, 1] -- deleting it cannot turn a test red, and no
# test claims otherwise. It is kept only for structural parity with formulas.noisy_or,
# which clamps both, so that the two implementations can be diffed line for line. Do not
# read it as a live guard, and do not remove the per-element clamp on the strength of it.
_CONFIDENCE_WRITE = """
MATCH (locked) WHERE elementId(locked) = $eid
CALL apoc.lock.nodes([locked])
WITH locked
MATCH (n:Provisional) WHERE elementId(n) = $eid
OPTIONAL MATCH (a:Article)-[m:MENTIONS]->(n)
OPTIONAL MATCH (a)-[:PUBLISHED_BY]->(s:Source)
WITH n,
     coalesce(a.story_cluster_id, a.source_guid_key) AS cluster,
     coalesce(s.credibility_score, 0.0) * coalesce(m.extraction_confidence, 0.0) AS c
WITH n, cluster, max(c) AS s_j
ORDER BY cluster
WITH n, [p IN collect([cluster,
         CASE WHEN s_j < 0.0 THEN 0.0 WHEN s_j > 1.0 THEN 1.0 ELSE s_j END])
         WHERE p[0] IS NOT NULL] AS pairs
WITH n, [p IN pairs | p[0]] AS clusters, [p IN pairs | p[1]] AS scores
WITH n, clusters, scores,
     1.0 - reduce(acc = 1.0, s IN scores | acc * (1.0 - s)) AS combined
SET n.contributing_story_cluster_ids = clusters,
    n.contributing_story_cluster_scores = scores,
    n.confidence = CASE WHEN combined < 0.0 THEN 0.0
                        WHEN combined > 1.0 THEN 1.0
                        ELSE combined END
"""


def rescan_confidence_batch(
    tx: ManagedTransaction, *, cursor: str | None, batch_size: int
) -> tuple[int, str | None]:
    """Rebuild provisional-node confidence for one page, from the graph (FR-ES-08).

    This is the repair path that lets `event_handler.py` claim a dropped, filtered-out or
    DLQ'd event costs freshness only and never correctness. Without it a lost MENTIONS
    event drops that cluster's contribution permanently: every other L4 write is a pure
    recompute, but node confidence ACCUMULATES, so nothing else would notice.

    It is also the only way out of the parallel-list poison pill.
    `refine_provisional_confidence` refuses to guess when
    `contributing_story_cluster_ids` and `..._scores` differ in length -- correctly, since
    ids alone cannot reconstruct scores -- and would otherwise raise on that node forever,
    sending every later MENTIONS event for it to the DLQ. Rebuilding from the MENTIONS
    edges needs neither list, so it repairs a node no event can.

    Unlike the event path this can lower a node's confidence, and must: a retracted
    MENTIONS edge (FR-RES-11) removes real evidence, and refinement alone only ever
    raises. Running it against a node whose events all landed is a no-op, because both
    compute the same thing -- the per-cluster MAX of credibility x extraction_confidence,
    combined with noisy-OR.

    Paging and scoring are two statements, and only the second one may decide anything:
    the rebuild happens inside `_CONFIDENCE_WRITE`, after its lock, so a refinement that
    commits between the page scan and the write is counted rather than clobbered.

    Returns (count, next cursor); a None cursor means the scan is exhausted.
    """
    rows = list(tx.run(_CONFIDENCE_SCAN, cursor=cursor, batch_size=batch_size))
    if not rows:
        return 0, None

    for row in rows:
        tx.run(_CONFIDENCE_WRITE, eid=row["eid"]).consume()

    # Advance past every row READ. Every row is written here, but keeping the rule
    # identical to the other scans is what guarantees termination if that ever changes.
    return len(rows), rows[-1]["eid"]


# Both flags are SET unconditionally to the predicate's value, never only to `true`:
# a flag that can turn on but not off is a ratchet, and re-running the sweep after an
# entity gains corroboration must clear it (FR-ES-10 idempotency).
#
# `IS :: ZONED DATETIME NOT NULL` rather than `IS NOT NULL`: duration.inSeconds RAISES on
# a string or a naive value, which would kill the whole page's transaction and stall the
# scan on one malformed node forever. L1 writes first_seen as a zoned datetime today, but
# a sweep that scans every provisional node in the graph is the wrong place to assume it.
# (`IS :: DATETIME` is a syntax error on Neo4j 6.2 -- the type is ZONED DATETIME.)
#
# `NOT NULL` is load-bearing, not decoration. Cypher types are NULLABLE by default, so
# `null IS :: ZONED DATETIME` is TRUE (verified on 6.2); the conjunction then evaluates
# to null for an undated node, and `SET n.prune_candidate = null` REMOVES the property
# instead of storing false. A consumer filtering `WHERE n.prune_candidate = false` would
# drop every healthy undated node -- which today is most of the graph.
_FLAG_NODES = """
MATCH (n:Provisional)
WHERE $cursor IS NULL OR elementId(n) > $cursor
WITH n ORDER BY elementId(n) LIMIT $batch_size
WITH n, (coalesce(n.confidence, 0.0) < $floor
         AND n.first_seen IS :: ZONED DATETIME NOT NULL
         AND duration.inSeconds(n.first_seen, $now).seconds / 86400.0 > $stale_days
        ) AS stale
SET n.prune_candidate = stale,
    n.prune_reason = CASE WHEN stale THEN 'stale_low_confidence_provisional' ELSE null END
RETURN elementId(n) AS eid
"""

# `NOT 'authoritative' IN origin`: an edge a feed also asserts is never a prune candidate,
# however long ago the inferred contribution was last corroborated.
_FLAG_EDGES = """
MATCH ()-[r]->()
WHERE r.inferred_confidence IS NOT NULL
  AND ($cursor IS NULL OR elementId(r) > $cursor)
WITH r ORDER BY elementId(r) LIMIT $batch_size
SET r.prune_candidate = (
    coalesce(r.confidence, 0.0) < $floor
    AND NOT 'authoritative' IN coalesce(r.origin, [])
)
RETURN elementId(r) AS eid
"""


def flag_pruning_batch(
    tx: ManagedTransaction,
    *,
    cursor: str | None,
    batch_size: int,
    knobs: ConfidenceKnobs,
    now: datetime,
    target: str,
) -> tuple[int, str | None]:
    """Flag one page of prune candidates (FR-ES-10). `target` is 'nodes' or 'edges'.

    L4 only FLAGS. Deletion and retention policy remain L1's -- this closes L1's open
    'Retention & pruning' note with a concrete input.
    """
    if target == "nodes":
        rows = list(tx.run(
            _FLAG_NODES, cursor=cursor, batch_size=batch_size,
            floor=knobs.prune_confidence_floor, stale_days=knobs.prune_stale_days, now=now,
        ))
    elif target == "edges":
        rows = list(tx.run(
            _FLAG_EDGES, cursor=cursor, batch_size=batch_size,
            floor=knobs.edge_confidence_floor,
        ))
    else:
        raise ValueError(f"unknown prune target: {target!r}")
    if not rows:
        return 0, None
    return len(rows), rows[-1]["eid"]
