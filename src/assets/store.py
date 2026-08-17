"""Asset node CRUD (design spec §3, §6). Asset is user-managed configuration, not
provenance/intel data, so delete is a hard delete, not the "flag, don't delete" pattern
used for scored/intel entities elsewhere in this codebase (design spec Decision 10)."""

from datetime import datetime, timezone
from typing import Any

from src.common.natural_keys import asset_key as _asset_key


def create_asset(
    tx, *, vendor: str, product: str, version: str, name: str | None = None
) -> dict[str, Any]:
    key = _asset_key(vendor, product, version)
    # Case-folded at WRITE time, matching `_split_cpe`'s handling of CPEMatch and
    # `asset_key`'s own folding. The matcher compares vendor/product with plain equality
    # so the Asset(vendor, product) / CPEMatch(vendor, product) indexes can serve it --
    # a `toLower()` in the query would plan as a full label scan instead.
    vendor, product = vendor.lower(), product.lower()
    row = tx.run(
        "MERGE (a:Asset {asset_key: $key}) "
        "ON CREATE SET a.vendor=$vendor, a.product=$product, a.version=$version, "
        "  a.name=$name, a.created_at=$now "
        "RETURN a.asset_key AS asset_key, a.vendor AS vendor, a.product AS product, "
        "  a.version AS version, a.name AS name, a.created_at AS created_at",
        key=key, vendor=vendor, product=product, version=version, name=name,
        now=datetime.now(timezone.utc).isoformat(),
    ).single()
    return dict(row)


def list_assets(tx) -> list[dict[str, Any]]:
    rows = tx.run(
        "MATCH (a:Asset) RETURN a.asset_key AS asset_key, a.vendor AS vendor, "
        "  a.product AS product, a.version AS version, a.name AS name, "
        "  a.created_at AS created_at ORDER BY a.created_at DESC"
    )
    return [dict(r) for r in rows]


def delete_asset(tx, *, asset_key: str) -> bool:
    result = tx.run("MATCH (a:Asset {asset_key: $key}) DETACH DELETE a", key=asset_key)
    return result.consume().counters.nodes_deleted > 0
