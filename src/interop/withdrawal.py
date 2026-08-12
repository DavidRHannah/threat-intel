"""Daily sweep phase: `exported`-but-now-gated-out objects get `revoked: true`
(FR-IO-08, interoperability-layer/design.md Part 5).

Same cursor-pagination contract as src/scoring/confidence.py::flag_pruning_batch, so
this drops into src/scoring/sweep_handler.py's PHASES loop unchanged (Task 3.2).

Only scans nodes carrying `exported = true` -- an object never served is never
withdrawn (nothing to withdraw), and `exported = false` (already revoked, or never
exported) is excluded from every future scan, so a revoked object is a stable end
state, not repeatedly re-flagged.
"""

from datetime import datetime

from src.common.graph.writer import _check_identifier
from src.interop.stix_ids import EXPORTABLE_NODE_LABELS

# A label-set predicate in WHERE (`any(l IN labels(n) WHERE l IN $labels)`) cannot use a
# label index and plans as an AllNodesScan (CLAUDE.md gotcha) -- interpolate a validated
# label union into the MATCH pattern instead, same as queries.py's _FETCH_NODES. Sourced
# from EXPORTABLE_NODE_LABELS (src/interop/stix_ids.py) rather than a second hardcoded
# list: a prior duplicate here had silently drifted and omitted `Source`.
_SCAN_PAGE = """
MATCH (n:{label_union})
WHERE n.exported = true
  AND ($cursor IS NULL OR elementId(n) > $cursor)
WITH n ORDER BY elementId(n) LIMIT $batch_size
RETURN elementId(n) AS eid
"""

# Revoke only within the fixed page of ids captured by _SCAN_PAGE above -- NOT a
# fresh `n.exported = true` re-query. A fresh re-query would silently drop rows this
# same batch just flipped to exported = false, shrinking the "scanned" set the
# cursor is based on and skipping over never-revisited nodes later in elementId
# order. (Caught empirically: with a page of 4 and batch_size 2, a page of
# [revoke, revoke, keep, revoke] left the last node permanently unrevoked because
# the cursor jumped past it.) Matching by elementId against the pre-mutation page
# keeps the scanned set and the revoked set counted over the same fixed rows.
_REVOKE_BY_ID = """
UNWIND $eids AS eid
MATCH (n) WHERE elementId(n) = eid
WITH n, (coalesce(n.confidence, 0.0) < $floor OR coalesce(n.prune_candidate, false)) AS gated_out
WHERE gated_out
SET n.revoked = true, n.exported = false, n.last_updated = $now
RETURN elementId(n) AS eid
"""


def revoke_batch(
    tx, *, cursor: str | None, batch_size: int, floor: float, now: datetime,
) -> tuple[int, str | None]:
    label_union = "|".join(
        _check_identifier(label, "label") for label in EXPORTABLE_NODE_LABELS
    )
    query = _SCAN_PAGE.format(label_union=label_union)
    scanned_rows = list(tx.run(query, cursor=cursor, batch_size=batch_size))
    eids = [row["eid"] for row in scanned_rows]
    next_cursor = eids[-1] if eids else None
    if not eids:
        return 0, next_cursor
    revoked_rows = list(
        tx.run(_REVOKE_BY_ID, eids=eids, floor=floor, now=now)
    )
    return len(revoked_rows), next_cursor
