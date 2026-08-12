"""Paginated `added_after` reads over exportable nodes/edges (FR-IO-04, FR-IO-07).

Same cursor-pagination shape as src/scoring/confidence.py's `flag_pruning_batch`:
`elementId` ordering, `$cursor IS NULL OR elementId(n) > $cursor`, `LIMIT $batch_size`,
next cursor = last row's elementId or None when the page is short.

The export gate (src/interop/gating.py) is applied IN Cypher, not filtered in Python
after the fact -- a `:Provisional` node or a below-floor edge must never even be
counted against `batch_size`, or a page could come back entirely gated-out and look
indistinguishable from "no more objects" to a naive caller.
"""

from datetime import datetime

from neo4j.time import DateTime as Neo4jDateTime

from src.common.graph.writer import _check_identifier
from src.interop.stix_ids import EXPORTABLE_NODE_LABELS

_EXPORTABLE_EDGE_TYPES = (
    "EXPLOITED_BY", "USES", "HAS_SAMPLE", "COMMUNICATES_WITH",
    "ASSOCIATED_WITH", "INDICATES", "ATTRIBUTED_TO",
)

_FETCH_NODES = """
MATCH (n:{label_union})
WHERE ($cursor IS NULL OR elementId(n) > $cursor)
  AND ($added_after IS NULL OR n.last_updated > $added_after)
  AND NOT n:Provisional
  AND NOT coalesce(n.prune_candidate, false)
  AND NOT coalesce(n.revoked, false)
  AND coalesce(n.confidence, 0.0) >= $floor
WITH n ORDER BY elementId(n) LIMIT $batch_size
RETURN elementId(n) AS eid, labels(n) AS labels, properties(n) AS props
"""

_FETCH_EDGES = """
MATCH (a)-[r:{rel_type_union}]->(b)
WHERE ($cursor IS NULL OR elementId(r) > $cursor)
  AND ($added_after IS NULL OR r.last_updated > $added_after)
  AND coalesce(r.confidence, 0.0) >= $floor
WITH r, a, b ORDER BY elementId(r) LIMIT $batch_size
RETURN elementId(r) AS eid, type(r) AS rel_type, properties(r) AS props,
       labels(a) AS start_labels, properties(a) AS start_props,
       labels(b) AS end_labels, properties(b) AS end_props
"""


def _primary_label(labels: list[str], candidates: tuple[str, ...]) -> str | None:
    for label in labels:
        if label in candidates:
            return label
    return None


def _normalize_props(props: dict) -> dict:
    """`properties(n)`/`properties(r)` return `neo4j.time.DateTime` for temporal
    properties, not a native `datetime` -- `src/interop/mapping.py`'s `_dt` helper (and
    any future caller, e.g. Task 3.1's withdrawal sweep) assumes the latter (verified
    against stix2==3.0.1: it raises `InvalidValueError` on the driver's own type).
    Normalizing here, at the single point every exportable node/edge property dict is
    read out of Neo4j, means every current and future caller of this module gets
    correctly-typed data for free instead of re-discovering or re-implementing this
    conversion per call site."""
    return {
        k: (v.to_native() if isinstance(v, Neo4jDateTime) else v) for k, v in props.items()
    }


def fetch_nodes_page(
    tx, *, cursor: str | None, batch_size: int, floor: float, added_after: datetime | None,
) -> tuple[list[dict], str | None]:
    label_union = "|".join(
        _check_identifier(label, "label") for label in EXPORTABLE_NODE_LABELS
    )
    query = _FETCH_NODES.format(label_union=label_union)
    rows = list(
        tx.run(
            query, cursor=cursor, batch_size=batch_size, floor=floor, added_after=added_after,
        )
    )
    results = [
        {
            "label": _primary_label(r["labels"], EXPORTABLE_NODE_LABELS),
            "props": _normalize_props(r["props"]),
        }
        for r in rows
        if _primary_label(r["labels"], EXPORTABLE_NODE_LABELS) is not None
    ]
    next_cursor = rows[-1]["eid"] if rows else None
    return results, next_cursor


def fetch_edges_page(
    tx, *, cursor: str | None, batch_size: int, floor: float, added_after: datetime | None,
) -> tuple[list[dict], str | None]:
    rel_union = "|".join(_check_identifier(t, "rel_type") for t in _EXPORTABLE_EDGE_TYPES)
    query = _FETCH_EDGES.format(rel_type_union=rel_union)
    rows = list(
        tx.run(
            query, cursor=cursor, batch_size=batch_size, floor=floor, added_after=added_after,
        )
    )
    results = [
        {
            "rel_type": r["rel_type"],
            "props": _normalize_props(r["props"]),
            "start_label": _primary_label(r["start_labels"], EXPORTABLE_NODE_LABELS),
            "start_props": _normalize_props(r["start_props"]),
            "end_label": _primary_label(r["end_labels"], EXPORTABLE_NODE_LABELS),
            "end_props": _normalize_props(r["end_props"]),
        }
        for r in rows
    ]
    next_cursor = rows[-1]["eid"] if rows else None
    return results, next_cursor


_FETCH_REVOKED_NODES = """
MATCH (n:{label_union})
WHERE n.revoked = true
  AND ($cursor IS NULL OR elementId(n) > $cursor)
  AND ($added_after IS NULL OR n.last_updated > $added_after)
WITH n ORDER BY elementId(n) LIMIT $batch_size
RETURN elementId(n) AS eid, labels(n) AS labels, properties(n) AS props
"""


def fetch_revoked_nodes_page(
    tx, *, cursor: str | None, batch_size: int, added_after,
) -> tuple[list[dict], str | None]:
    """Sweep-flagged revocations (Task 3.1) live ON the node/edge -- deliberately NOT
    gated by confidence/floor here, unlike fetch_nodes_page: a revoked object's whole
    point is that it now FAILS the normal gate, so gating this query the same way would
    make Task 3.1's write permanently unservable.

    Applies `_normalize_props` (the neo4j.time.DateTime -> native datetime conversion
    added when Task 2.2's review relocated it here) for the same reason every other
    fetcher in this module does: the caller calls `.isoformat()` on `last_updated`,
    which `neo4j.time.DateTime` does not support the same way a native datetime does."""
    label_union = "|".join(
        _check_identifier(label, "label") for label in EXPORTABLE_NODE_LABELS
    )
    query = _FETCH_REVOKED_NODES.format(label_union=label_union)
    rows = list(
        tx.run(query, cursor=cursor, batch_size=batch_size, added_after=added_after)
    )
    results = [
        {
            "label": _primary_label(r["labels"], EXPORTABLE_NODE_LABELS),
            "props": _normalize_props(r["props"]),
        }
        for r in rows
        if _primary_label(r["labels"], EXPORTABLE_NODE_LABELS) is not None
    ]
    next_cursor = rows[-1]["eid"] if rows else None
    return results, next_cursor


def scan_revoked_tombstones(*, added_after) -> list[dict]:
    """Reconciliation-merge tombstones (Task 1.4) -- the merged-away node no longer
    exists in Neo4j at all, so this is the one query in this module that reads
    DynamoDB instead of the graph. A `scan` is acceptable at this table's expected
    volume (reconciliation merges of already-exported entities are rare); revisit with
    a GSI on `revoked_at` if that stops being true.

    The table's env-var wiring is an infra-stack concern outside this task's scope
    (Task 1.4 wrote to it with no default and no deploy-time wiring yet). In `local`
    dev specifically, a missing config value means "no tombstones table provisioned
    in this environment" -- degrade to zero tombstones rather than taking down the
    whole Objects endpoint (which also serves sweep-revoked and normal node/edge/
    report objects in the same response). Outside `local`, `get_config` raises the
    SAME `KeyError` for a genuinely missing SSM parameter as it does for the
    local-no-default case, so swallowing it unconditionally would silently mask a
    real dev/prod misconfiguration as "zero tombstones" forever -- with no
    CloudWatch alarm anywhere in this repo to ever surface it. Only degrade in
    `local`; re-raise everywhere else."""
    import boto3

    from src.common.config import _current_env, get_config

    try:
        table_name = get_config("revoked_stix_ids_table_name")
    except KeyError:
        if _current_env() == "local":
            return []
        raise  # dev/prod: a missing table config is a real misconfiguration, not a no-op.
    table = boto3.resource("dynamodb").Table(table_name)
    response = table.scan()
    items = response.get("Items", [])
    if added_after is None:
        return items
    cutoff = added_after.isoformat()
    return [item for item in items if item["revoked_at"] > cutoff]


def mark_exported(tx, label: str, key: dict) -> None:
    ((key_prop, key_value),) = key.items()
    query = (
        f"MATCH (n:{_check_identifier(label, 'label')} "
        f"{{{_check_identifier(key_prop, 'key property')}: $key_value}}) "
        "SET n.exported = true"
    )
    tx.run(query, key_value=key_value).consume()


def mark_exported_edge(
    tx, rel_type: str, start_label: str, start_key: dict, end_label: str, end_key: dict,
) -> None:
    ((start_prop, start_value),) = start_key.items()
    ((end_prop, end_value),) = end_key.items()
    query = (
        f"MATCH (a:{_check_identifier(start_label, 'label')} "
        f"{{{_check_identifier(start_prop, 'key property')}: $start_value}})"
        f"-[r:{_check_identifier(rel_type, 'rel_type')}]->"
        f"(b:{_check_identifier(end_label, 'label')} "
        f"{{{_check_identifier(end_prop, 'key property')}: $end_value}}) "
        "SET r.exported = true"
    )
    tx.run(query, start_value=start_value, end_value=end_value).consume()
