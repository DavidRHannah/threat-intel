"""graph-writes SNS consumer: stamps `last_updated` on every node/edge write it sees.

`last_updated` is declared in technical-specification.md sec 3 as a common field on
every node but is written by no layer today (design spec sec 2, gap #1). L5's
added_after polling (FR-IO-04, src/interop/queries.py) depends on it, so this Lambda
starts writing it from its own deploy date forward. An object untouched since before
this ships has no `last_updated` at all and exports with created == modified on first
sight -- an honest default, never a fabricated update time.

Node_merge handling (FR-IO-09) is Task 1.4 -- added to this module's dispatch, not a
separate handler, so there is one graph-writes subscription for all of L5's needs.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any

from src.common.graph.writer import _check_identifier
from src.common.neo4j_driver import get_driver

logger = logging.getLogger(__name__)

_STAMP_NODE = """
MATCH (n:{label} {{{key_prop}: $key_value}})
SET n.last_updated = $event_time
"""

_STAMP_EDGE = """
MATCH (a:{start_label} {{{start_key_prop}: $start_value}})
      -[r:{rel_type}]->
      (b:{end_label} {{{end_key_prop}: $end_value}})
SET r.last_updated = $event_time
"""


def _event_time(message: dict) -> datetime:
    raw = message.get("event_time")
    if not raw:
        return datetime.now(timezone.utc)
    try:
        parsed = datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        return datetime.now(timezone.utc)
    return parsed


def _stamp_node(tx, label: str, key: dict, event_time: datetime) -> bool:
    if not key or len(key) != 1:
        return False
    ((key_prop, key_value),) = key.items()
    query = _STAMP_NODE.format(
        label=_check_identifier(label, "label"),
        key_prop=_check_identifier(key_prop, "key property"),
    )
    summary = tx.run(query, key_value=key_value, event_time=event_time).consume()
    return summary.counters.properties_set > 0


def _stamp_edge(
    tx, rel_type: str, start_label: str, start_key: dict, end_label: str, end_key: dict,
    event_time: datetime,
) -> bool:
    if not start_key or len(start_key) != 1 or not end_key or len(end_key) != 1:
        return False
    ((start_prop, start_value),) = start_key.items()
    ((end_prop, end_value),) = end_key.items()
    query = _STAMP_EDGE.format(
        rel_type=_check_identifier(rel_type, "rel_type"),
        start_label=_check_identifier(start_label, "label"),
        start_key_prop=_check_identifier(start_prop, "key property"),
        end_label=_check_identifier(end_label, "label"),
        end_key_prop=_check_identifier(end_prop, "key property"),
    )
    summary = tx.run(
        query, start_value=start_value, end_value=end_value, event_time=event_time,
    ).consume()
    return summary.counters.properties_set > 0


def _handle_node_write(message: dict, driver, event_time: datetime) -> bool:
    label = message.get("label")
    key = message.get("key")
    if not label or not key:
        return False
    with driver.session() as session:
        return session.execute_write(_stamp_node, label, key, event_time)


def _handle_edge_write(message: dict, driver, event_time: datetime) -> bool:
    rel_type = message.get("rel_type")
    start_label = message.get("start_label")
    end_label = message.get("end_label")
    if not rel_type or not start_label or not end_label:
        # Pre-labelled messages (see event_handler.py's own fallback note) carry no
        # label to stamp against safely -- skip rather than guess an edge to touch.
        return False
    with driver.session() as session:
        return session.execute_write(
            _stamp_edge, rel_type, start_label, message.get("start_key"),
            end_label, message.get("end_key"), event_time,
        )


def _handle_article(message: dict, driver, event_time: datetime) -> bool:
    article_id = message.get("article_id")
    if not article_id:
        return False
    with driver.session() as session:
        return session.execute_write(
            _stamp_node, "Article", {"source_guid_key": article_id}, event_time,
        )


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    driver = get_driver()
    processed = 0
    skipped = 0

    for record in event.get("Records", []):
        message = json.loads(record["Sns"]["Message"])
        message_type = message.get("message_type")
        event_time = _event_time(message)

        if message_type == "node_write":
            did = _handle_node_write(message, driver, event_time)
        elif message_type == "edge_write":
            did = _handle_edge_write(message, driver, event_time)
        elif message_type == "article":
            did = _handle_article(message, driver, event_time)
        elif message_type == "node_merge":
            # Imported here, not at module level: src.interop.merge_tombstone does not
            # exist until Task 1.4, and this branch is the only thing that needs it. A
            # module-level import would break every one of THIS task's own tests before
            # Task 1.4 ever runs.
            from src.interop.merge_tombstone import handle_node_merge

            did = handle_node_merge(message, event_time)
        else:
            did = False

        processed += int(did)
        skipped += int(not did)

    return {"processed": processed, "skipped": skipped}
