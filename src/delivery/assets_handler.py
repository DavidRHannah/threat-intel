"""Asset CRUD + matched-CVE reads (design spec §6). POST/DELETE are the only write paths
in DeliveryStack -- every other Delivery handler is read-only (FR-DEL-09); this is a
deliberate, explicitly-called-out exception (design spec Decision 8)."""

import json

from src.assets.matcher import match_asset
from src.assets.store import create_asset, delete_asset, list_assets
from src.common.neo4j_driver import get_driver
from src.delivery._response import _response
from src.delivery.queries import (
    fetch_cves_for_all_assets,
    fetch_cves_for_asset,
    fetch_known_vendor_products,
)


def create_asset_handler(event, context) -> dict:
    payload = json.loads(event.get("body") or "{}")
    vendor, product, version = payload.get("vendor"), payload.get("product"), payload.get("version")
    if not (vendor and product and version):
        return _response(400, {"error": "vendor, product, and version are required"})

    driver = get_driver()
    with driver.session() as session:
        asset = session.execute_write(
            lambda tx: create_asset(tx, vendor=vendor, product=product, version=version, name=payload.get("name"))
        )
        hits = session.execute_write(lambda tx: match_asset(tx, asset=asset))
    return _response(201, {"asset": asset, "match_count": len(hits)})


def list_assets_handler(event, context) -> dict:
    driver = get_driver()
    with driver.session() as session:
        assets = session.execute_read(list_assets)
    return _response(200, {"assets": assets})


def delete_asset_handler(event, context) -> dict:
    asset_key = (event.get("pathParameters") or {}).get("id")
    driver = get_driver()
    with driver.session() as session:
        deleted = session.execute_write(lambda tx: delete_asset(tx, asset_key=asset_key))
    if not deleted:
        return _response(404, {"error": "asset not found"})
    return _response(200, {"deleted": asset_key})


def asset_cves_handler(event, context) -> dict:
    asset_key = (event.get("pathParameters") or {}).get("id")
    driver = get_driver()
    with driver.session() as session:
        cves = session.execute_read(lambda tx: fetch_cves_for_asset(tx, asset_key=asset_key))
    return _response(200, {"cves": cves})


def all_assets_cves_handler(event, context) -> dict:
    driver = get_driver()
    with driver.session() as session:
        cves = session.execute_read(fetch_cves_for_all_assets)
    return _response(200, {"cves": cves})


def known_vendor_products_handler(event, context) -> dict:
    # `q` narrows the autocomplete server-side. Without it the LIMIT truncates the whole
    # label alphabetically at production scale rather than paging a filtered set -- see
    # `fetch_known_vendor_products`.
    q = (event.get("queryStringParameters") or {}).get("q") or ""
    driver = get_driver()
    with driver.session() as session:
        pairs = session.execute_read(lambda tx: fetch_known_vendor_products(tx, q=q))
    return _response(200, {"vendor_products": pairs})
