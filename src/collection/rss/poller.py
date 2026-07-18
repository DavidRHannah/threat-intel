"""RSS/Atom Poller Lambda (L1 Task 4).

On a schedule, polls the active feeds in the `Sources` DynamoDB table concurrently,
detects new/changed articles via a content fingerprint, and publishes a
discovery/update event per item onto the `discovery-updates` SQS queue for L1's
Extraction Lambda (Task 5) to consume.

FR-DC-04 (Must): sources are fanned out concurrently (`ThreadPoolExecutor`), each with
a per-source timeout so one hanging feed cannot block the others. The fetch itself is
bounded at the socket level (`httpx` timeout in `_default_fetch`) so a genuine network
hang raises a bounded, retryable exception instead of blocking the worker thread (and
therefore `ThreadPoolExecutor.shutdown(wait=True)`) indefinitely. `PollingState` writes
are owned exclusively by the worker (`_poll_one_source`) — the dispatcher's
`future.result(timeout=...)` backstop only annotates the response payload on timeout,
never writes PollingState, so a source is never recorded twice in one cycle.
FR-DC-05 (Should): polling tiers/frequency are handled by the EventBridge schedule(s)
that invoke this Lambda (CDK-level, Task 12) — out of scope here.
FR-DC-06 (Must): a fetch that raises (timeout/connection-error/5xx) is retried within
the same invocation, capped at `rss_retry_cap`, with exponential backoff.
FR-DC-07/08 (Must): the poller Lambda is deployed with `reserved_concurrent_executions=1`
so at most one invocation runs at a time. That is a CDK construct property, not testable
at this layer — see `test_data_collection_stack.py` (Task 12).
FR-DC-09/10 (Must): a never-seen GUID publishes a `discovery` event; a seen GUID whose
fingerprint changed publishes an `update` event; a seen GUID with an unchanged
fingerprint publishes nothing.
FR-DC-11 (Must): the SQS publish for an item happens *before* its fingerprint is
written to DedupState (the pipeline's at-least-once ordering invariant — a crash after
publish-but-before-write simply re-publishes on retry; the reverse would silently drop
the item forever).
FR-DC-14/15 (Should): a source failing `health_alert_threshold` consecutive times
triggers an injected `alert_fn`.

All external seams (the feed fetcher, the SQS client, the DynamoDB tables, the alert
callback, the backoff sleep, and the fetched_at clock) are injected parameters so tests
drive this module with fakes rather than monkeypatching `feedparser` or `boto3`.
"""

import datetime
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Any, Callable

from src.collection.rss.dedup_state import (
    get_fingerprint,
    put_fingerprint,
    record_poll_outcome,
)
from src.common.config import get_config


def compute_fingerprint(title: str, summary: str, link: str) -> str:
    """The content fingerprint used to detect new/changed articles (FR-DC-09/10)."""
    return hashlib.sha256(f"{title}{summary}{link}".encode()).hexdigest()


def _entry_field(entry: Any, key: str, default: str = "") -> str:
    value = entry.get(key, default)
    return value if value is not None else default


def _entry_guid(entry: Any) -> str:
    return _entry_field(entry, "id") or _entry_field(entry, "guid") or _entry_field(entry, "link")


def _default_alert_fn(source_id: str, consecutive_failures: int) -> None:
    """Fallback alert_fn: swallow silently. Production callers must inject a real one
    (e.g. an SNS publish) — this default only exists so tests/handler don't crash when
    the (Should, not Must) alerting path isn't wired up yet."""


def _default_fetched_at() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _fetch_with_retry(
    source: dict,
    fetch_fn: Callable[[dict], Any],
    retry_cap: int,
    sleep_fn: Callable[[float], None],
) -> Any:
    """Call fetch_fn(source), retrying on exception up to retry_cap additional times
    with exponential backoff (FR-DC-06). Raises the last exception if all attempts
    fail."""
    max_attempts = retry_cap + 1
    last_exc: Exception | None = None
    for attempt in range(max_attempts):
        try:
            return fetch_fn(source)
        except Exception as exc:  # noqa: BLE001 - any fetch failure is retryable
            last_exc = exc
            if attempt < max_attempts - 1:
                sleep_fn(0.1 * (2**attempt))
    assert last_exc is not None
    raise last_exc


def _check_health_alert(
    polling_table: Any,
    source_id: str,
    health_alert_threshold: int,
    alert_fn: Callable[[str, int], None],
) -> None:
    response = polling_table.get_item(Key={"source_id": source_id})
    item = response.get("Item", {})
    consecutive_failures = item.get("consecutive_failures", 0)
    if consecutive_failures >= health_alert_threshold:
        alert_fn(source_id, consecutive_failures)


def _poll_one_source(
    source: dict,
    fetch_fn: Callable[[dict], Any],
    dedup_table: Any,
    polling_table: Any,
    sqs_client: Any,
    queue_url: str,
    retry_cap: int,
    sleep_fn: Callable[[float], None],
    fetched_at_fn: Callable[[], str],
    health_alert_threshold: int,
    alert_fn: Callable[[str, int], None],
) -> dict:
    source_id = source["source_id"]
    try:
        parsed = _fetch_with_retry(source, fetch_fn, retry_cap, sleep_fn)
    except Exception as exc:  # noqa: BLE001 - record and move on to the next source
        record_poll_outcome(polling_table, source_id, success=False)
        _check_health_alert(polling_table, source_id, health_alert_threshold, alert_fn)
        return {"source_id": source_id, "error": str(exc)}

    events_published = 0
    for entry in parsed.entries:
        guid = _entry_guid(entry)
        title = _entry_field(entry, "title")
        summary = _entry_field(entry, "summary")
        link = _entry_field(entry, "link")
        published_at = _entry_field(entry, "published")

        fingerprint = compute_fingerprint(title, summary, link)
        existing_fingerprint = get_fingerprint(dedup_table, source_id, guid)

        if existing_fingerprint == fingerprint:
            continue  # seen, unchanged: publish nothing (FR-DC-09/10)

        event_type = "discovery" if existing_fingerprint is None else "update"
        payload = {
            "event_type": event_type,
            "source_id": source_id,
            "guid": guid,
            "title": title,
            "summary": summary,
            "link": link,
            "published_at": published_at,
            "fetched_at": fetched_at_fn(),
        }
        # FR-DC-11: publish before writing the fingerprint. A crash between these two
        # calls re-publishes on the next poll (safe, at-least-once); the reverse order
        # would mark the item "seen" while nobody downstream ever heard about it.
        sqs_client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(payload))
        put_fingerprint(dedup_table, source_id, guid, fingerprint)
        events_published += 1

    record_poll_outcome(polling_table, source_id, success=True)
    return {"source_id": source_id, "events_published": events_published}


def poll_sources(
    sources: list[dict],
    fetch_fn: Callable[[dict], Any],
    dedup_table: Any,
    polling_table: Any,
    sqs_client: Any,
    queue_url: str,
    *,
    timeout_seconds: float | None = None,
    retry_cap: int | None = None,
    health_alert_threshold: int | None = None,
    alert_fn: Callable[[str, int], None] | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    fetched_at_fn: Callable[[], str] = _default_fetched_at,
) -> list[dict]:
    """Poll every source in `sources` concurrently and return one result dict per
    source. Never raises for a single source's failure or timeout — that source's
    outcome is recorded and the cycle proceeds for the rest (FR-DC-04)."""
    if timeout_seconds is None:
        timeout_seconds = float(get_config("rss_poll_timeout_seconds", default="8"))
    if retry_cap is None:
        retry_cap = int(get_config("rss_retry_cap", default="3"))
    if health_alert_threshold is None:
        health_alert_threshold = int(get_config("health_alert_threshold", default="6"))
    if alert_fn is None:
        alert_fn = _default_alert_fn

    if not sources:
        return []

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=len(sources)) as executor:
        future_to_source = {
            executor.submit(
                _poll_one_source,
                source,
                fetch_fn,
                dedup_table,
                polling_table,
                sqs_client,
                queue_url,
                retry_cap,
                sleep_fn,
                fetched_at_fn,
                health_alert_threshold,
                alert_fn,
            ): source
            for source in sources
        }
        for future, source in future_to_source.items():
            source_id = source["source_id"]
            try:
                results.append(future.result(timeout=timeout_seconds))
            except FuturesTimeoutError:
                # NOTE: this does NOT cancel the worker thread — Python threads cannot
                # be force-killed. `record_poll_outcome`/`_check_health_alert` are
                # deliberately NOT called here: the worker (`_poll_one_source`) is the
                # sole owner of PollingState writes for this source and will record
                # its own outcome (success or failure) whenever it actually finishes,
                # exactly once. Writing here too would double-write PollingState in
                # the same cycle. This branch exists only to surface a timeout in the
                # response payload for observability; the executor's `__exit__`
                # (`shutdown(wait=True)`) still waits for the worker to finish, but
                # since `_default_fetch` now bounds the real fetch at the socket level
                # (see below), a genuine network hang can no longer block that wait
                # indefinitely. A pathological non-network hang (e.g. an infinite loop
                # inside feed parsing) is not solvable this way and remains bounded
                # only by the Lambda function's own timeout.
                results.append({"source_id": source_id, "error": "timeout"})
    return results


def _default_fetch(source: dict, timeout_seconds: float) -> Any:
    """Fetch the feed bytes over HTTP with a bounded socket-level timeout, then hand
    them to feedparser. Fetching via `httpx` (rather than letting feedparser open the
    connection itself) is what bounds a genuine network hang: feedparser.parse(url)
    sets no timeout of its own and can block forever on a hung socket, which the
    outer `future.result(timeout=...)` does not prevent (it only stops the *caller*
    waiting; the worker thread keeps running until ThreadPoolExecutor.shutdown(wait=True)
    joins it). A bounded httpx timeout raises an httpx exception instead, which
    `_fetch_with_retry`'s blanket except already treats as retryable."""
    import feedparser
    import httpx

    response = httpx.get(source["url"], timeout=timeout_seconds, follow_redirects=True)
    response.raise_for_status()
    return feedparser.parse(response.content)


def handler(event: dict, context: Any) -> dict:
    """Lambda entry point. Relies on the Lambda's ambient AWS region — never a
    hardcoded one (NFR-MAINT-01)."""
    import functools

    import boto3

    dynamodb = boto3.resource("dynamodb")
    sources_table = dynamodb.Table("Sources")
    dedup_table = dynamodb.Table("DedupState")
    polling_table = dynamodb.Table("PollingState")
    sqs_client = boto3.client("sqs")
    queue_url = get_config("discovery_updates_queue_url")
    timeout_seconds = float(get_config("rss_poll_timeout_seconds", default="8"))

    sources = sources_table.scan().get("Items", [])
    results = poll_sources(
        sources,
        functools.partial(_default_fetch, timeout_seconds=timeout_seconds),
        dedup_table,
        polling_table,
        sqs_client,
        queue_url,
        timeout_seconds=timeout_seconds,
    )
    return {"sources_polled": len(sources), "results": results}
