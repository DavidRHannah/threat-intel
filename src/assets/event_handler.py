"""graph-writes SNS consumer: matches a newly-written CPEMatch against every Asset with the
same vendor/product (design spec §5). The daily sweep (sweep_handler.py) is the correctness
net for anything this misses -- same relationship L4's event_handler has to its sweep."""

import json
import logging
from datetime import datetime, timezone
from typing import Any

from src.assets.matcher import write_affects_edge
from src.assets.matching import version_satisfies
from src.common.graph.publish import MESSAGE_TYPE_NODE_WRITE
from src.common.neo4j_driver import get_driver

logger = logging.getLogger(__name__)


def _match_and_assets(tx, match_criteria_id: str) -> tuple[list[dict], list[dict]]:
    """All (CVE, CPEMatch) rows for this match id, plus every Asset sharing its
    vendor/product.

    Returns EVERY referencing CVE, not one. `matchCriteriaId` is deliberately shared
    across CVEs (see `test_resync_matches_removes_stale_edge_but_not_the_shared_node`),
    and a `LIMIT 1` here silently dropped the AFFECTS edge for every CVE but one while
    the handler still reported success.

    The Asset lookup compares vendor/product with plain equality against already
    case-folded values (`create_asset` folds at write time), so it can use
    `asset_vendor_product_index`; `toLower()` on the property would not.
    """
    rows = [
        dict(r)
        for r in tx.run(
            "MATCH (m:CPEMatch {match_criteria_id: $id})<-[:MATCHES]-(c:CVE) "
            "RETURN c.cve_id AS cve_id, m.vendor AS vendor, m.product AS product, "
            "  m.version AS version, m.version_start_including AS version_start_including, "
            "  m.version_start_excluding AS version_start_excluding, "
            "  m.version_end_including AS version_end_including, "
            "  m.version_end_excluding AS version_end_excluding, m.vulnerable AS vulnerable",
            id=match_criteria_id,
        )
    ]
    if not rows:
        return [], []
    assets = list(
        tx.run(
            "MATCH (a:Asset {vendor: $vendor, product: $product}) "
            "RETURN a.asset_key AS asset_key, a.version AS version",
            vendor=(rows[0]["vendor"] or "").lower(),
            product=(rows[0]["product"] or "").lower(),
        )
    )
    return rows, [dict(r) for r in assets]


def _handle_cpe_match_write(message: dict, driver) -> bool:
    if message.get("label") != "CPEMatch":
        return False
    match_criteria_id = (message.get("key") or {}).get("match_criteria_id")
    if not match_criteria_id:
        return False

    did = False
    now = datetime.now(timezone.utc)
    with driver.session() as session:
        def _tx(tx):
            nonlocal did
            matches, assets = _match_and_assets(tx, match_criteria_id)
            if not matches:
                return
            # Every CVE referencing this CPEMatch gets its own AFFECTS edge -- the
            # version bounds are a property of the shared match, so a satisfied asset
            # is affected by all of them, not just the first one the query happened to
            # return.
            for match in matches:
                for asset in assets:
                    if not version_satisfies(asset["version"], match):
                        continue
                    write_affects_edge(
                        tx, cve_id=match["cve_id"], asset_key=asset["asset_key"],
                        match_criteria_id=match_criteria_id, now=now,
                    )
                    did = True

        session.execute_write(_tx)
    return did


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    driver = get_driver()
    processed = 0
    skipped = 0
    for record in event.get("Records", []):
        message = json.loads(record["Sns"]["Message"])
        did = False
        if message.get("message_type") == MESSAGE_TYPE_NODE_WRITE:
            did = _handle_cpe_match_write(message, driver)
        processed += int(did)
        skipped += int(not did)
    return {"processed": processed, "skipped": skipped}
