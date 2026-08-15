"""Tests for src.collection.rss.poller (RSS/Atom Poller Lambda, L1 Task 4).

FR-DC-04, FR-DC-06, FR-DC-09, FR-DC-10, FR-DC-11, FR-DC-14, FR-DC-15.

All external seams (feed fetcher, SQS client, DynamoDB tables, alert callback, backoff
sleep) are injected fakes — no monkeypatching of `feedparser` or `boto3`.
"""

import json
import time
from types import SimpleNamespace

import boto3
import pytest
from moto import mock_aws

from src.collection.rss.poller import compute_fingerprint, poll_sources


@pytest.fixture
def aws_credentials(monkeypatch):
    """moto needs a region + dummy credentials; production code never hardcodes a
    region (NFR-MAINT-01) — this is test-only."""
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")


@pytest.fixture
def dedup_table(aws_credentials):
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="DedupState",
            KeySchema=[
                {"AttributeName": "source_id", "KeyType": "HASH"},
                {"AttributeName": "guid", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "source_id", "AttributeType": "S"},
                {"AttributeName": "guid", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table


@pytest.fixture
def polling_table(aws_credentials):
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="PollingState",
            KeySchema=[{"AttributeName": "source_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "source_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table


class FakeSQS:
    """Records every send_message call (payload + a call-order log entry)."""

    def __init__(self, log=None):
        self.log = log if log is not None else []
        self.sent = []

    def send_message(self, QueueUrl, MessageBody):
        self.log.append("sqs.send_message")
        self.sent.append(json.loads(MessageBody))
        return {"MessageId": "fake-message-id"}


class CountingPollingTable:
    """Wraps a real (moto) PollingState table, counting update_item calls per
    source_id so tests can assert `record_poll_outcome` writes exactly once per
    source per cycle (the double-write regression pin)."""

    def __init__(self, table):
        self._table = table
        self.update_counts: dict[str, int] = {}

    def get_item(self, **kwargs):
        return self._table.get_item(**kwargs)

    def update_item(self, **kwargs):
        source_id = kwargs["Key"]["source_id"]
        self.update_counts[source_id] = self.update_counts.get(source_id, 0) + 1
        return self._table.update_item(**kwargs)

    def put_item(self, **kwargs):
        return self._table.put_item(**kwargs)


class PutLoggingTable:
    """Wraps a real (moto) DynamoDB table, logging only put_item calls, so the
    FR-DC-11 ordering test's log contains exactly the two calls it cares about."""

    def __init__(self, table, log):
        self._table = table
        self._log = log

    def get_item(self, **kwargs):
        return self._table.get_item(**kwargs)

    def put_item(self, **kwargs):
        self._log.append("dynamodb.put_item")
        return self._table.put_item(**kwargs)

    def update_item(self, **kwargs):
        return self._table.update_item(**kwargs)


def make_feed(entries):
    return SimpleNamespace(entries=entries)


def make_entry(guid, title, summary, link, published="2026-07-16T00:00:00Z"):
    return {
        "id": guid,
        "title": title,
        "summary": summary,
        "link": link,
        "published": published,
    }


# --- FR-DC-09 / FR-DC-10 ----------------------------------------------------------


def test_discovery_unchanged_and_update_events(dedup_table, polling_table):
    """A never-seen GUID publishes 'discovery'; a seen+unchanged GUID publishes
    nothing; a seen+changed GUID publishes 'update' (FR-DC-09, FR-DC-10)."""
    source = {"source_id": "src-1", "url": "http://example.com/feed"}

    unchanged_fp = compute_fingerprint("Same Title", "Same Summary", "http://x/unchanged")
    dedup_table.put_item(
        Item={"source_id": "src-1", "guid": "unchanged-guid", "content_fingerprint": unchanged_fp}
    )
    dedup_table.put_item(
        Item={"source_id": "src-1", "guid": "changed-guid", "content_fingerprint": "stale-fingerprint"}
    )

    entries = [
        make_entry("new-guid", "New Title", "New Summary", "http://x/new"),
        make_entry("unchanged-guid", "Same Title", "Same Summary", "http://x/unchanged"),
        make_entry("changed-guid", "Changed Title", "Changed Summary", "http://x/changed"),
    ]

    def fetch_fn(_source):
        return make_feed(entries)

    sqs = FakeSQS()
    results = poll_sources(
        [source],
        fetch_fn,
        dedup_table,
        polling_table,
        sqs,
        "http://queue-url",
        timeout_seconds=1,
        retry_cap=3,
        health_alert_threshold=6,
        sleep_fn=lambda _seconds: None,
    )

    assert results == [{"source_id": "src-1", "events_published": 2}]

    by_guid = {msg["guid"]: msg for msg in sqs.sent}
    assert set(by_guid) == {"new-guid", "changed-guid"}
    assert by_guid["new-guid"]["event_type"] == "discovery"
    assert by_guid["changed-guid"]["event_type"] == "update"


# --- FR-DC-11 ----------------------------------------------------------------------


def test_publish_happens_before_fingerprint_write(dedup_table, polling_table):
    """The ordering invariant: SQS publish must happen before DynamoDB put_item for
    the fingerprint (FR-DC-11) — never the reverse."""
    source = {"source_id": "src-1", "url": "http://example.com/feed"}
    entries = [make_entry("new-guid", "Title", "Summary", "http://x/new")]

    def fetch_fn(_source):
        return make_feed(entries)

    call_log: list[str] = []
    sqs = FakeSQS(log=call_log)
    logged_dedup_table = PutLoggingTable(dedup_table, call_log)

    poll_sources(
        [source],
        fetch_fn,
        logged_dedup_table,
        polling_table,
        sqs,
        "http://queue-url",
        timeout_seconds=1,
        retry_cap=3,
        health_alert_threshold=6,
        sleep_fn=lambda _seconds: None,
    )

    assert call_log == ["sqs.send_message", "dynamodb.put_item"]


# --- FR-DC-06 ------------------------------------------------------------------------


def test_fetch_retried_within_configured_cap(dedup_table, polling_table):
    """A fetch that raises once (simulated 5xx/timeout) then succeeds is retried
    within the same invocation; retries stay within rss_retry_cap (FR-DC-06)."""
    source = {"source_id": "src-1", "url": "http://example.com/feed"}
    entries = [make_entry("new-guid", "Title", "Summary", "http://x/new")]

    call_count = {"n": 0}

    def flaky_fetch_fn(_source):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise ConnectionError("simulated 5xx")
        return make_feed(entries)

    sleeps: list[float] = []
    sqs = FakeSQS()
    results = poll_sources(
        [source],
        flaky_fetch_fn,
        dedup_table,
        polling_table,
        sqs,
        "http://queue-url",
        timeout_seconds=1,
        retry_cap=3,
        health_alert_threshold=6,
        sleep_fn=sleeps.append,
    )

    assert results == [{"source_id": "src-1", "events_published": 1}]
    assert call_count["n"] == 2  # one failure + one success
    assert call_count["n"] - 1 <= 3  # retries stayed within rss_retry_cap
    assert len(sqs.sent) == 1


def test_fetch_retry_stops_at_cap_under_persistent_failure(dedup_table, polling_table):
    """A fetch that ALWAYS raises is attempted exactly retry_cap + 1 times, not more
    (FR-DC-06 cap under persistent failure — the happy-path retry test above only
    proves single-transient recovery, which is trivially <= the cap)."""
    source = {"source_id": "src-1", "url": "http://example.com/feed"}
    retry_cap = 3
    call_count = {"n": 0}

    def always_fails(_source):
        call_count["n"] += 1
        raise ConnectionError("simulated persistent 5xx")

    sqs = FakeSQS()
    results = poll_sources(
        [source],
        always_fails,
        dedup_table,
        polling_table,
        sqs,
        "http://queue-url",
        timeout_seconds=1,
        retry_cap=retry_cap,
        health_alert_threshold=6,
        sleep_fn=lambda _seconds: None,
    )

    assert call_count["n"] == retry_cap + 1
    assert results == [{"source_id": "src-1", "error": "simulated persistent 5xx"}]


# --- FR-DC-04 ------------------------------------------------------------------------


def test_concurrent_dispatch_one_hanging_source_does_not_block_others(dedup_table, polling_table):
    """3 sources are dispatched concurrently; one hangs past its per-source timeout,
    but the cycle still completes for the other two (FR-DC-04). Also pins the
    single-write invariant: `record_poll_outcome` must be written exactly once per
    source in the cycle, even for the source whose future timed out from the
    dispatcher's point of view but whose worker later finishes on its own (the
    double-write regression this task fixes)."""
    sources = [
        {"source_id": "src-1", "url": "http://example.com/feed1"},
        {"source_id": "src-2", "url": "http://example.com/feed2"},
        {"source_id": "src-3", "url": "http://example.com/feed3"},
    ]
    invoked = {"src-1": False, "src-2": False, "src-3": False}

    def fetch_fn(source):
        invoked[source["source_id"]] = True
        if source["source_id"] == "src-2":
            time.sleep(0.3)  # simulated hang, well past the test's small timeout
            return make_feed([])
        return make_feed([])

    sqs = FakeSQS()
    counting_polling_table = CountingPollingTable(polling_table)
    start = time.monotonic()
    results = poll_sources(
        sources,
        fetch_fn,
        dedup_table,
        counting_polling_table,
        sqs,
        "http://queue-url",
        timeout_seconds=0.05,
        retry_cap=0,
        health_alert_threshold=6,
        sleep_fn=lambda _seconds: None,
    )
    elapsed = time.monotonic() - start

    assert all(invoked.values())  # all 3 fetch functions were dispatched
    by_source = {r["source_id"]: r for r in results}
    assert by_source["src-1"]["events_published"] == 0
    assert by_source["src-3"]["events_published"] == 0
    assert by_source["src-2"]["error"] == "timeout"
    # bounded by the hanging fetch's own sleep, not by any real 8s default
    assert elapsed < 2

    # Single-write invariant (regression pin for the double-write finding): the
    # ThreadPoolExecutor context manager's __exit__ has already joined every worker
    # by the time poll_sources returns, so src-2's worker has finished and recorded
    # its own outcome by now. Every source — including src-2 — must have exactly one
    # PollingState write in this cycle, never two.
    assert counting_polling_table.update_counts == {"src-1": 1, "src-2": 1, "src-3": 1}


# --- FR-DC-14 / FR-DC-15 ---------------------------------------------------------------


def test_health_alert_fires_after_consecutive_failure_threshold(dedup_table, polling_table):
    """A source failing health_alert_threshold consecutive times triggers alert_fn
    (FR-DC-14, FR-DC-15)."""
    source = {"source_id": "src-1", "url": "http://example.com/feed"}

    def always_fails(_source):
        raise ConnectionError("simulated persistent 5xx")

    alerts: list[tuple[str, int]] = []

    def alert_fn(source_id, consecutive_failures):
        alerts.append((source_id, consecutive_failures))

    sqs = FakeSQS()
    for _ in range(6):
        poll_sources(
            [source],
            always_fails,
            dedup_table,
            polling_table,
            sqs,
            "http://queue-url",
            timeout_seconds=1,
            retry_cap=0,
            health_alert_threshold=6,
            alert_fn=alert_fn,
            sleep_fn=lambda _seconds: None,
        )

    assert alerts == [("src-1", 6)]


def test_rss_sources_excludes_non_rss_rows():
    """FR-DC-04: the poller scans the whole Sources table, which also holds `api` rows
    (NVD, CISA KEV, MITRE ATT&CK...). Feeding those to the RSS fetcher makes it download
    and parse multi-megabyte JSON as a feed -- the real Lambda died with
    Runtime.OutOfMemory once the table held more than the single seeded RSS row.
    """
    from src.collection.rss.poller import rss_sources

    items = [
        {"source_id": "krebs", "type": "rss", "url": "https://krebsonsecurity.com/feed/"},
        {"source_id": "mitre_attck", "type": "api", "url": "https://example/attack.json"},
        {"source_id": "nvd", "type": "api", "url": "https://example/nvd"},
        {"source_id": "legacy-no-type", "url": "https://example/feed"},
    ]

    assert [s["source_id"] for s in rss_sources(items)] == ["krebs"]
