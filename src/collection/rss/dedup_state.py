"""DynamoDB access for polling health (PollingState) and per-article dedup
(DedupState) state.

Both tables are injected as `boto3` DynamoDB table resources — this module opens no
client/resource of its own. The table name/region/credentials are resolved by the
caller (a Lambda resolves the table from an env var set by CDK; tests inject a moto
fixture table). See `technical-specification.md` for the table schemas:

- `DedupState`: partition `source_id`, sort `guid` -> `content_fingerprint`.
- `PollingState`: partition `source_id` -> `consecutive_failures`, `last_success_at`.

FR-DC-09/10/11, FR-DC-14.
"""

import datetime
from typing import Any


def get_fingerprint(table: Any, source_id: str, guid: str) -> str | None:
    """Return the stored content fingerprint for (source_id, guid), or None if the
    item has never been seen (FR-DC-09)."""
    response = table.get_item(Key={"source_id": source_id, "guid": guid})
    item = response.get("Item")
    if item is None:
        return None
    return item["content_fingerprint"]


def put_fingerprint(table: Any, source_id: str, guid: str, fingerprint: str) -> None:
    """Store the content fingerprint for (source_id, guid) (FR-DC-10/11)."""
    table.put_item(
        Item={
            "source_id": source_id,
            "guid": guid,
            "content_fingerprint": fingerprint,
        }
    )


def record_poll_outcome(
    table: Any, source_id: str, *, success: bool, success_at: str | None = None
) -> None:
    """Record the outcome of a poll attempt for source_id (FR-DC-14).

    On failure, increments `consecutive_failures`. On success, resets
    `consecutive_failures` to 0 and sets `last_success_at`. Callers whose next poll window
    must start exactly where this poll's fetch window ended (the NVD delta) pass
    `success_at` — the single instant captured before the fetch — so the stored watermark
    is that same instant, not a later `now()` that would open a self-widening gap. When
    omitted, the current UTC time is used (the RSS poller, whose window is not watermarked).
    """
    if success:
        stamp = success_at or datetime.datetime.now(datetime.timezone.utc).isoformat()
        table.update_item(
            Key={"source_id": source_id},
            UpdateExpression="SET consecutive_failures = :zero, last_success_at = :now",
            ExpressionAttributeValues={
                ":zero": 0,
                ":now": stamp,
            },
        )
    else:
        table.update_item(
            Key={"source_id": source_id},
            UpdateExpression="SET consecutive_failures = if_not_exists(consecutive_failures, :zero) + :one",
            ExpressionAttributeValues={
                ":zero": 0,
                ":one": 1,
            },
        )
