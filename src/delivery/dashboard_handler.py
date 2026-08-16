"""Dashboard read-API Lambda handlers (FR-DEL-01, FR-DEL-09).

Six thin API-Gateway-proxy handlers, each: parse query/path params, run one read-only Cypher
query (src/delivery/queries.py), return a JSON envelope. No graph writes on this path.
"""

import json
from datetime import datetime, timedelta, timezone

from src.common.neo4j_driver import get_driver
from src.delivery.knobs import DeliveryKnobs
from src.delivery.queries import (
    fetch_recent_stories,
    fetch_stats,
    fetch_subgraph,
    fetch_top_actors,
    fetch_top_campaigns,
    fetch_top_cves,
    fetch_top_malware,
)


def _response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


def _limit_param(event: dict, default: int) -> int:
    params = (event or {}).get("queryStringParameters") or {}
    raw = params.get("limit")
    return int(raw) if raw else default


def stats_handler(event, context) -> dict:
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=7)
    driver = get_driver()
    with driver.session() as session:
        stats = session.execute_read(
            lambda tx: fetch_stats(
                tx, today_start=today_start.isoformat(), week_start=week_start.isoformat(),
            )
        )
    return _response(200, stats)


def top_cves_handler(event, context) -> dict:
    knobs = DeliveryKnobs.from_config()
    limit = _limit_param(event, knobs.dashboard_default_limit)
    driver = get_driver()
    with driver.session() as session:
        rows = session.execute_read(lambda tx: fetch_top_cves(tx, limit=limit))
    return _response(200, {"cves": rows})


def top_actors_handler(event, context) -> dict:
    knobs = DeliveryKnobs.from_config()
    limit = _limit_param(event, knobs.dashboard_default_limit)
    driver = get_driver()
    with driver.session() as session:
        rows = session.execute_read(lambda tx: fetch_top_actors(tx, limit=limit))
    return _response(200, {"actors": rows})


def top_malware_handler(event, context) -> dict:
    knobs = DeliveryKnobs.from_config()
    limit = _limit_param(event, knobs.dashboard_default_limit)
    driver = get_driver()
    with driver.session() as session:
        rows = session.execute_read(lambda tx: fetch_top_malware(tx, limit=limit))
    return _response(200, {"malware": rows})


def top_campaigns_handler(event, context) -> dict:
    knobs = DeliveryKnobs.from_config()
    limit = _limit_param(event, knobs.dashboard_default_limit)
    driver = get_driver()
    with driver.session() as session:
        rows = session.execute_read(lambda tx: fetch_top_campaigns(tx, limit=limit))
    return _response(200, {"campaigns": rows})


def recent_stories_handler(event, context) -> dict:
    knobs = DeliveryKnobs.from_config()
    limit = _limit_param(event, knobs.dashboard_default_limit * 2)
    driver = get_driver()
    with driver.session() as session:
        rows = session.execute_read(lambda tx: fetch_recent_stories(tx, limit=limit))
    return _response(200, {"stories": rows})


def subgraph_handler(event, context) -> dict:
    element_id = (event.get("pathParameters") or {}).get("id")
    if not element_id:
        return _response(400, {"error": "missing id"})
    driver = get_driver()
    with driver.session() as session:
        result = session.execute_read(lambda tx: fetch_subgraph(tx, element_id=element_id))
    if result is None:
        return _response(404, {"error": "not found"})
    return _response(200, result)
