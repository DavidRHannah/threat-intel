"""Reconciliation: merge `:Provisional` nodes into a newly created/updated
canonical entity node (Phase 2, Step 2.3 of `plans/02-nlp.md`, FR-RES-08,
FR-RES-09, FR-RES-10).

`reconcile()` is the reconciliation logic itself, callable independently of
any Lambda handler -- the `graph-writes` SNS subscription wiring for this is
Phase 5's job (CDK), not this module's.

Given a canonical node's key/label, this searches for `:Provisional` nodes of
the same label whose normalized name is:
  - an EXACT match against the canonical's own normalized name/aliases ->
    Case A: auto-merge (FR-RES-08, FR-RES-10). Edge re-pointing, alias
    folding, and provisional deletion all happen while both nodes are held
    locked via `apoc.lock.nodes` on an elementId-ordered pair -- the exact
    locking primitive `src/common/graph/writer.py::merge_relationship`
    already uses elsewhere in this codebase (reused here directly rather
    than reinvented, since re-pointing an unbounded set of arbitrary-typed
    edges isn't expressible through that function's single-rel-type MERGE
    API). `apoc.refactor.mergeNodes` performs the actual edge move + node
    deletion atomically inside that locked scope.
  - a FUZZY match (edit-distance close, but not exact) -> Case B: no merge;
    a review-queue row is written to DynamoDB instead (FR-RES-09).
  - neither -> left alone entirely.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from datetime import datetime, timezone

import boto3
from neo4j import Driver

from src.common.config import get_config
from src.common.graph.publish import publish_node_merge

# Below this ratio a provisional is considered unrelated to the canonical
# entity and is left alone (no merge, no review-queue row) -- otherwise every
# provisional in the graph would eventually get queued for review against
# every canonical node.
_FUZZY_REVIEW_THRESHOLD = 0.6


@dataclass
class ReconciliationResult:
    merged: bool
    merged_provisional_keys: list[str] = field(default_factory=list)
    queued_for_review: list[str] = field(default_factory=list)


def _normalize(name: str) -> str:
    return " ".join(name.strip().lower().split())


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fetch_canonical(tx, canonical_merge_key: str, canonical_label: str) -> dict | None:
    record = tx.run(
        f"MATCH (c:{canonical_label} {{merge_key: $key}}) "
        "RETURN c.name AS name, coalesce(c.aliases, []) AS aliases",
        key=canonical_merge_key,
    ).single()
    if record is None:
        return None
    return {"name": record["name"], "aliases": record["aliases"]}


def _fetch_provisionals(tx, canonical_label: str) -> list[dict]:
    records = tx.run(
        f"MATCH (p:{canonical_label}:Provisional) "
        "RETURN p.merge_key AS merge_key, p.name AS name"
    )
    return [{"merge_key": r["merge_key"], "name": r["name"]} for r in records]


def _merge_provisional_into_canonical(
    tx, *, canonical_label: str, canonical_merge_key: str, provisional_merge_key: str,
    provisional_name: str,
) -> bool:
    record = tx.run(
        f"""
        MATCH (p:{canonical_label}:Provisional {{merge_key: $provisional_key}}),
              (c:{canonical_label} {{merge_key: $canonical_key}})
        WITH p, c,
             CASE WHEN elementId(p) <= elementId(c) THEN [p, c] ELSE [c, p] END AS ordered
        CALL apoc.lock.nodes(ordered)
        WITH c, p
        MATCH (p2) WHERE elementId(p2) = elementId(p)
        WITH c, p, coalesce(p2.exported, false) AS was_exported
        CALL apoc.refactor.mergeNodes([c, p], {{properties: "discard", mergeRels: true}})
        YIELD node
        SET node.aliases = CASE
            WHEN $provisional_name IN coalesce(node.aliases, []) THEN node.aliases
            ELSE coalesce(node.aliases, []) + [$provisional_name]
        END
        RETURN was_exported
        """,
        provisional_key=provisional_merge_key,
        canonical_key=canonical_merge_key,
        provisional_name=provisional_name,
    ).single()
    return bool(record["was_exported"])


def _queue_for_review(provisional_merge_key: str, canonical_merge_key: str) -> None:
    table_name = get_config("reconciliation_review_queue_table_name")
    table = boto3.resource("dynamodb").Table(table_name)
    table.put_item(
        Item={
            "provisional_merge_key": provisional_merge_key,
            "candidate_merge_key": canonical_merge_key,
            "queued_at": _now().isoformat(),
        }
    )


def reconcile(driver: Driver, canonical_merge_key: str, canonical_label: str) -> ReconciliationResult:
    with driver.session() as session:
        canonical = session.execute_read(
            _fetch_canonical, canonical_merge_key, canonical_label
        )
        if canonical is None:
            return ReconciliationResult(merged=False)

        canonical_aliases_normalized = {_normalize(canonical["name"] or "")} | {
            _normalize(a) for a in canonical["aliases"]
        }
        canonical_aliases_normalized.discard("")

        provisionals = session.execute_read(_fetch_provisionals, canonical_label)

    merged_keys: list[str] = []
    queued_keys: list[str] = []

    for provisional in provisionals:
        provisional_key = provisional["merge_key"]
        normalized_provisional = _normalize(provisional_key)

        if normalized_provisional in canonical_aliases_normalized:
            with driver.session() as session:
                was_exported = session.execute_write(
                    _merge_provisional_into_canonical,
                    canonical_label=canonical_label,
                    canonical_merge_key=canonical_merge_key,
                    provisional_merge_key=provisional_key,
                    provisional_name=provisional["name"] or provisional_key,
                )
            merged_keys.append(provisional_key)
            if was_exported:
                # Published AFTER the transaction commits, same convention as every
                # other graph-writes publisher in this codebase (publish.py docstring).
                publish_node_merge(
                    label=canonical_label,
                    old_key={"merge_key": provisional_key},
                    new_key={"merge_key": canonical_merge_key},
                )
            continue

        best_ratio = max(
            (
                difflib.SequenceMatcher(a=normalized_provisional, b=alias).ratio()
                for alias in canonical_aliases_normalized
            ),
            default=0.0,
        )
        if best_ratio >= _FUZZY_REVIEW_THRESHOLD:
            _queue_for_review(provisional_key, canonical_merge_key)
            queued_keys.append(provisional_key)

    return ReconciliationResult(
        merged=bool(merged_keys),
        merged_provisional_keys=merged_keys,
        queued_for_review=queued_keys,
    )
