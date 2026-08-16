"""Daily full Asset<->CPEMatch reconciliation (design spec §5, §7). Catches anything the
event path missed. Cursor-paginated over Asset.asset_key so one invocation never scans
the whole table -- same one-invocation-per-page shape as src/scoring/sweep_handler.py."""

from datetime import datetime, timezone
from typing import Any

from src.assets.matcher import candidate_matches_for, write_affects_edge
from src.assets.matching import version_satisfies
from src.common.neo4j_driver import get_driver


def _batch_size() -> int:
    from src.common.config import get_config

    return int(get_config("assets_sweep_batch_size", default="500"))


def _fetch_page(tx, *, cursor: str | None, batch_size: int) -> list[dict]:
    rows = tx.run(
        "MATCH (a:Asset) WHERE $cursor IS NULL OR a.asset_key > $cursor "
        "RETURN a.asset_key AS asset_key, a.vendor AS vendor, a.product AS product, "
        "  a.version AS version ORDER BY a.asset_key LIMIT $batch_size",
        cursor=cursor, batch_size=batch_size,
    )
    return [dict(r) for r in rows]


def _reconcile_asset(tx, asset: dict, now: datetime) -> None:
    """Reuses Task 6's candidate_matches_for/write_affects_edge rather than re-querying
    or re-writing with its own Cypher (see this task's Interfaces note)."""
    for candidate in candidate_matches_for(tx, vendor=asset["vendor"], product=asset["product"]):
        if not version_satisfies(asset["version"], candidate):
            continue
        write_affects_edge(
            tx, cve_id=candidate["cve_id"], asset_key=asset["asset_key"],
            match_criteria_id=candidate["match_criteria_id"], now=now,
        )


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    cursor = event.get("cursor") or None
    now = datetime.now(timezone.utc)
    driver = get_driver()
    batch_size = _batch_size()

    with driver.session() as session:
        page = session.execute_read(lambda tx: _fetch_page(tx, cursor=cursor, batch_size=batch_size))
        for asset in page:
            session.execute_write(lambda tx, a=asset: _reconcile_asset(tx, a, now))

    nxt = page[-1]["asset_key"] if len(page) == batch_size else None
    return {"cursor": nxt or "", "done": nxt is None, "count": len(page)}
