"""Matches one Asset against candidate CPEMatch records and writes AFFECTS edges
(design spec §5). Version comparison is pure Python (src.assets.matching); Cypher here
only fetches candidates and writes the resulting edge -- same split as L4's
formulas.py + thin Cypher (design spec Decision 7)."""

from datetime import datetime, timezone
from typing import Any

from src.assets.matching import version_satisfies
from src.common.graph.writer import merge_relationship


def candidate_matches_for(tx, *, vendor: str, product: str) -> list[dict[str, Any]]:
    """Candidate (CVE, CPEMatch) rows for one vendor/product pair.

    Compares vendor/product with plain equality against already-case-folded stored values
    (`_split_cpe`/`create_asset` fold at write time), folding the ARGUMENTS here in Python
    instead. A `toLower(m.vendor)` predicate is a function call on the indexed property
    and cannot use `cpe_match_vendor_product_index` — it planned as a full label scan over
    the largest label in the graph on every sweep page and every match event.
    """
    rows = tx.run(
        "MATCH (m:CPEMatch {vendor: $vendor, product: $product})<-[:MATCHES]-(c:CVE) "
        "RETURN c.cve_id AS cve_id, m.match_criteria_id AS match_criteria_id, "
        "  m.version AS version, m.version_start_including AS version_start_including, "
        "  m.version_start_excluding AS version_start_excluding, "
        "  m.version_end_including AS version_end_including, "
        "  m.version_end_excluding AS version_end_excluding, m.vulnerable AS vulnerable",
        vendor=vendor.lower(), product=product.lower(),
    )
    return [dict(r) for r in rows]


def write_affects_edge(
    tx, *, cve_id: str, asset_key: str, match_criteria_id: str, now: datetime
) -> None:
    """The one place an AFFECTS edge is written. match_asset, the event handler
    (Task 7), and the sweep (Task 8) all call this instead of each hand-rolling their
    own merge_relationship call -- do not reintroduce a second copy of this Cypher."""
    merge_relationship(
        tx,
        start_label="CVE", start_key={"cve_id": cve_id},
        end_label="Asset", end_key={"asset_key": asset_key},
        rel_type="AFFECTS",
        on_create={"matched_at": now.isoformat(), "matched_via": match_criteria_id},
        on_match={"matched_at": now.isoformat(), "matched_via": match_criteria_id},
    )


def write_affects_edges_bulk(tx, *, rows: list[dict], now: datetime) -> int:
    """UNWIND-batched equivalent of `write_affects_edge` for many AFFECTS edges at once.

    `rows` are `{"cve_id", "asset_key", "match_criteria_id"}` dicts. One round trip for
    the whole batch instead of one `merge_relationship` call (each taking its own
    `apoc.lock.nodes`) per edge — the plan's own Global Constraints require the sweep to
    batch from the start, citing this codebase's EPSS/ATT&CK/ThreatFox history of exactly
    this one-round-trip-per-row shape timing out in production. Same UNWIND shape as
    `src.common.graph.assertion_edges.upsert_authoritative_assertions_bulk`.

    Endpoints are locked in deterministic elementId order (matching `merge_relationship`
    and `assertion_edges`) so a concurrent writer cannot deadlock against this one.
    """
    if not rows:
        return 0
    result = tx.run(
        "UNWIND $rows AS row "
        "MATCH (c:CVE {cve_id: row.cve_id}), (a:Asset {asset_key: row.asset_key}) "
        "WITH c, a, row, CASE WHEN elementId(c) <= elementId(a) THEN [c, a] ELSE [a, c] END "
        "  AS ordered "
        "CALL apoc.lock.nodes(ordered) "
        "WITH c, a, row "
        "MERGE (c)-[r:AFFECTS]->(a) "
        "SET r.matched_at = $now, r.matched_via = row.match_criteria_id "
        "RETURN count(r) AS n",
        rows=rows, now=now.isoformat(),
    ).single()
    return result["n"] if result else 0


def delete_affects_edges_bulk(tx, *, rows: list[dict]) -> int:
    """Retract AFFECTS edges that no longer reflect a real match, one round trip for all.

    `rows` are `{"cve_id", "asset_key"}` dicts. The sweep is a FULL reconciliation, so it
    must correct in both directions — NVD flipping `vulnerable` to false, narrowing a
    version range, or dropping a cpeMatch outright all leave a stale edge that nothing
    else removes. Same compute-wanted-set / delete-the-difference shape as
    `resync_categorized_as` / `resync_matches`.

    AFFECTS is a derived match fact about the user's own inventory, not provenance/intel,
    so it is genuinely deleted rather than flagged — same reasoning that makes Asset
    deletion a hard delete (design spec Decision 10).
    """
    if not rows:
        return 0
    result = tx.run(
        "UNWIND $rows AS row "
        "MATCH (:CVE {cve_id: row.cve_id})-[r:AFFECTS]->(:Asset {asset_key: row.asset_key}) "
        "DELETE r "
        "RETURN count(*) AS n",
        rows=rows,
    ).single()
    return result["n"] if result else 0


def match_asset(tx, *, asset: dict, now: datetime | None = None) -> list[str]:
    at = now or datetime.now(timezone.utc)
    candidates = candidate_matches_for(tx, vendor=asset["vendor"], product=asset["product"])
    hit_ids: list[str] = []
    for candidate in candidates:
        if not version_satisfies(asset["version"], candidate):
            continue
        write_affects_edge(
            tx, cve_id=candidate["cve_id"], asset_key=asset["asset_key"],
            match_criteria_id=candidate["match_criteria_id"], now=at,
        )
        hit_ids.append(candidate["match_criteria_id"])
    return hit_ids
