"""Tombstones a reconciled-away STIX id (FR-IO-09).

`apoc.refactor.mergeNodes` (src/nlp/resolution/reconciliation.py) deletes the
provisional node synchronously -- by the time `publish_node_merge`'s message reaches
this consumer, there is nothing left in the graph to stamp `revoked` on. A small
DynamoDB table is the one piece of export state this layer keeps outside Neo4j (design
spec sec 3 decision 9), same pattern as the pre-existing `ReconciliationReviewQueue`
table (technical-specification.md sec 5).

Task 2.2's Objects handler reads this table for entries with `revoked_at` after the
poller's `added_after` cursor and emits a stub `revoked: true` object for each --
same-day visibility, rather than waiting for the next daily sweep.
"""

from datetime import datetime

import boto3

from src.common.config import get_config
from src.interop.knobs import InteropKnobs
from src.interop.stix_ids import stix_id


def handle_node_merge(message: dict, event_time: datetime) -> bool:
    label = message.get("label")
    old_key = message.get("old_key")
    new_key = message.get("new_key")
    if not label or not old_key or not new_key or len(old_key) != 1 or len(new_key) != 1:
        return False

    knobs = InteropKnobs.from_config()
    ((_, old_value),) = old_key.items()
    ((_, new_value),) = new_key.items()
    old_stix_id = stix_id(label, old_value, namespace=knobs.stix_namespace)
    new_stix_id = stix_id(label, new_value, namespace=knobs.stix_namespace)

    table_name = get_config("revoked_stix_ids_table_name")
    table = boto3.resource("dynamodb").Table(table_name)
    table.put_item(
        Item={
            "stix_id": old_stix_id,
            "revoked_at": event_time.isoformat(),
            "reason": "reconciled",
            "superseded_by": new_stix_id,
        }
    )
    return True
