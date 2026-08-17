"""Daily full Asset<->CPEMatch reconciliation (design spec §5, §7). Catches anything the
event path missed. Cursor-paginated over Asset.asset_key so one invocation never scans
the whole table -- same one-invocation-per-page shape as src/scoring/sweep_handler.py.

Two properties this handler must have, both fixed after the final whole-branch review:

1. It RECONCILES, it does not merely add. An AFFECTS edge whose match no longer holds
   (NVD flipped `vulnerable` to false, narrowed a version range, or dropped the cpeMatch)
   is retracted. Nothing else in the system removes one -- the event path only ever
   writes -- so an add-only sweep leaves a permanently growing set of false positives,
   which is worse than a missing match for a feature whose entire value proposition is
   "only what is actually relevant to what I run".

2. It is UNWIND-BATCHED per page, not per row. The plan's Global Constraints call for
   this explicitly, citing the EPSS / MITRE ATT&CK / ThreatFox bugs already fixed in this
   codebase -- each of which was one `execute_write` (or one `session.run`) per row
   against remote AuraDB, and each of which silently failed to finish inside its Lambda
   timeout. One asset matching several hundred CVEs is exactly that shape. Round trips
   per page are now a constant plus the edge-write batches, not O(assets x matches).
"""

from datetime import datetime, timezone
from typing import Any

from src.assets.matcher import delete_affects_edges_bulk, write_affects_edges_bulk
from src.assets.matching import version_satisfies
from src.common.neo4j_driver import get_driver


def _batch_size() -> int:
    """Assets per invocation (the pagination page size)."""
    from src.common.config import get_config

    return int(get_config("assets_sweep_batch_size", default="500"))


def _edge_batch_size() -> int:
    """AFFECTS edges per UNWIND round trip. Separate from the page size so a small page
    (or a test forcing single-asset pages) does not also shrink the write batch."""
    from src.common.config import get_config

    return int(get_config("assets_edge_batch_size", default="500"))


def _fetch_page(tx, *, cursor: str | None, batch_size: int) -> list[dict]:
    rows = tx.run(
        "MATCH (a:Asset) WHERE $cursor IS NULL OR a.asset_key > $cursor "
        "RETURN a.asset_key AS asset_key, a.vendor AS vendor, a.product AS product, "
        "  a.version AS version ORDER BY a.asset_key LIMIT $batch_size",
        cursor=cursor, batch_size=batch_size,
    )
    return [dict(r) for r in rows]


def _fetch_candidates(tx, *, pairs: list[dict]) -> list[dict]:
    """Candidate (CVE, CPEMatch) rows for EVERY vendor/product pair on this page, in one
    round trip -- the batched equivalent of calling `candidate_matches_for` per asset.

    Compares vendor/product with plain equality against already case-folded stored values
    (`_split_cpe`/`create_asset` fold at write time) so the query uses
    `cpe_match_vendor_product_index` instead of scanning the label; `toLower()` on the
    property would defeat the index.
    """
    if not pairs:
        return []
    rows = tx.run(
        "UNWIND $pairs AS p "
        "MATCH (m:CPEMatch {vendor: p.vendor, product: p.product})<-[:MATCHES]-(c:CVE) "
        "RETURN p.vendor AS vendor, p.product AS product, c.cve_id AS cve_id, "
        "  m.match_criteria_id AS match_criteria_id, m.version AS version, "
        "  m.version_start_including AS version_start_including, "
        "  m.version_start_excluding AS version_start_excluding, "
        "  m.version_end_including AS version_end_including, "
        "  m.version_end_excluding AS version_end_excluding, m.vulnerable AS vulnerable",
        pairs=pairs,
    )
    return [dict(r) for r in rows]


def _fetch_existing_affects(tx, *, asset_keys: list[str]) -> list[dict]:
    """Every AFFECTS edge currently pointing at any asset on this page, in one round
    trip. The retraction set is the difference between this and the recomputed matches."""
    if not asset_keys:
        return []
    rows = tx.run(
        "UNWIND $keys AS key "
        "MATCH (c:CVE)-[:AFFECTS]->(:Asset {asset_key: key}) "
        "RETURN key AS asset_key, c.cve_id AS cve_id",
        keys=asset_keys,
    )
    return [dict(r) for r in rows]


def _chunks(rows: list, size: int):
    for i in range(0, len(rows), size):
        yield rows[i:i + size]


def _wanted_rows(page: list[dict], candidates: list[dict]) -> list[dict]:
    """Pure: the AFFECTS edges this page's assets should have, given the candidates.

    Version comparison stays in pure Python (design spec Decision 7) -- Cypher only
    fetches and writes.
    """
    by_pair: dict[tuple[str, str], list[dict]] = {}
    for candidate in candidates:
        by_pair.setdefault((candidate["vendor"], candidate["product"]), []).append(candidate)

    wanted: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for asset in page:
        key = ((asset["vendor"] or "").lower(), (asset["product"] or "").lower())
        for candidate in by_pair.get(key, []):
            if not version_satisfies(asset["version"], candidate):
                continue
            pair = (candidate["cve_id"], asset["asset_key"])
            if pair in seen:
                continue  # two CPEMatch records can justify the same edge; write it once
            seen.add(pair)
            wanted.append({
                "cve_id": candidate["cve_id"],
                "asset_key": asset["asset_key"],
                "match_criteria_id": candidate["match_criteria_id"],
            })
    return wanted


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    cursor = event.get("cursor") or None
    now = datetime.now(timezone.utc)
    driver = get_driver()
    batch_size = _batch_size()
    edge_batch_size = _edge_batch_size()

    written = 0
    retracted = 0
    with driver.session() as session:
        page = session.execute_read(
            lambda tx: _fetch_page(tx, cursor=cursor, batch_size=batch_size)
        )
        if page:
            pairs = sorted({
                ((a["vendor"] or "").lower(), (a["product"] or "").lower()) for a in page
            })
            candidates = session.execute_read(
                lambda tx: _fetch_candidates(
                    tx, pairs=[{"vendor": v, "product": p} for v, p in pairs]
                )
            )
            wanted = _wanted_rows(page, candidates)

            asset_keys = [a["asset_key"] for a in page]
            existing = session.execute_read(
                lambda tx: _fetch_existing_affects(tx, asset_keys=asset_keys)
            )
            wanted_pairs = {(r["cve_id"], r["asset_key"]) for r in wanted}
            stale = [
                {"cve_id": e["cve_id"], "asset_key": e["asset_key"]}
                for e in existing
                if (e["cve_id"], e["asset_key"]) not in wanted_pairs
            ]

            for chunk in _chunks(wanted, edge_batch_size):
                written += session.execute_write(
                    lambda tx, c=chunk: write_affects_edges_bulk(tx, rows=c, now=now)
                )
            for chunk in _chunks(stale, edge_batch_size):
                retracted += session.execute_write(
                    lambda tx, c=chunk: delete_affects_edges_bulk(tx, rows=c)
                )

    nxt = page[-1]["asset_key"] if len(page) == batch_size else None
    return {
        "cursor": nxt or "",
        "done": nxt is None,
        "count": len(page),
        "written": written,
        "retracted": retracted,
    }
