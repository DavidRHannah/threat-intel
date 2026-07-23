"""Unit tests for the thin Lambda `handler()` wrappers added in L1 Task 12.

These verify the *wiring* the handlers add on top of the already-tested library
functions — the poller's env-var table-name resolution (the deployed-name fix; a
literal `Table("Sources")` would `ResourceNotFoundException` in any real env), and that
each new REST/STIX handler resolves its seams and calls its library function through.
The library behavior itself is covered by Tasks 4-11's own tests and is not re-tested.
"""

import boto3
import pytest
from moto import mock_aws

from src.collection.rest import abusech, cisa_kev, epss, ghsa, nvd, otx
from src.collection.rss import poller
from src.collection.stix import attck_sync


@pytest.fixture
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")


@pytest.fixture
def polling_table(aws_credentials):
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="crossroads-test-pollingstate",
            KeySchema=[{"AttributeName": "source_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "source_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table


class _FakeDriver:
    """A driver stand-in the handlers only pass through — never dereferenced here."""


class _FakeSources:
    def scan(self):
        return {"Items": [{"source_id": "s1"}]}


class _TableRouter:
    """Stands in for a boto3 DynamoDB resource, logging every Table() name requested."""

    def __init__(self, log):
        self.log = log

    def Table(self, name):  # noqa: N802 - mirrors boto3's resource API
        self.log.append(name)
        return _FakeSources() if name.endswith("sources") else object()


def test_poller_handler_reads_deployed_table_names_from_env(monkeypatch):
    """The deployed tables are `crossroads-{env}-{name}`, not the literal short names the
    original handler hardcoded. handler() must resolve them from the env vars the stack
    sets, or it ResourceNotFoundExceptions in every real env."""
    monkeypatch.setenv("SOURCES_TABLE_NAME", "crossroads-dev-sources")
    monkeypatch.setenv("DEDUP_STATE_TABLE_NAME", "crossroads-dev-dedupstate")
    monkeypatch.setenv("POLLING_STATE_TABLE_NAME", "crossroads-dev-pollingstate")

    requested_tables: list[str] = []
    # handler does a local `import boto3`; patch the real module it binds from.
    monkeypatch.setattr(boto3, "resource", lambda *a, **k: _TableRouter(requested_tables))
    monkeypatch.setattr(boto3, "client", lambda *a, **k: object())
    def fake_get_config(name, default=None):
        return "https://queue.example/url" if name == "discovery_updates_queue_url" else default

    monkeypatch.setattr(poller, "get_config", fake_get_config)

    captured = {}

    def fake_poll_sources(sources, *a, **k):
        captured["sources"] = sources
        return [{"source_id": "s1", "events_published": 0}]

    monkeypatch.setattr(poller, "poll_sources", fake_poll_sources)

    result = poller.handler({}, None)

    assert "crossroads-dev-sources" in requested_tables
    assert "crossroads-dev-dedupstate" in requested_tables
    assert "crossroads-dev-pollingstate" in requested_tables
    assert result["sources_polled"] == 1
    assert captured["sources"] == [{"source_id": "s1"}]


def test_poller_handler_missing_table_env_var_is_a_hard_error(monkeypatch):
    monkeypatch.delenv("SOURCES_TABLE_NAME", raising=False)
    monkeypatch.setattr(boto3, "resource", lambda *a, **k: _TableRouter([]))
    monkeypatch.setattr(boto3, "client", lambda *a, **k: object())
    with pytest.raises(KeyError):
        poller.handler({}, None)


def test_nvd_handler_reads_last_success_at_and_records_outcome(polling_table, monkeypatch):
    monkeypatch.setenv("POLLING_STATE_TABLE_NAME", "crossroads-test-pollingstate")
    polling_table.put_item(
        Item={"source_id": "nvd", "last_success_at": "2026-07-01T00:00:00+00:00", "consecutive_failures": 3}
    )

    seen = {}

    def fake_poll(driver, http_client, last_success_at):
        seen["last_success_at"] = last_success_at
        seen["driver"] = driver
        return 7, "2026-07-23T00:00:00+00:00"

    monkeypatch.setattr(nvd, "poll_nvd_delta", fake_poll)
    driver = _FakeDriver()
    result = nvd.handler({}, None, driver=driver, http_client=object())

    assert result == {"cves_updated": 7}
    assert seen["last_success_at"] == "2026-07-01T00:00:00+00:00"
    assert seen["driver"] is driver
    # Success recorded -> consecutive_failures reset to 0.
    item = polling_table.get_item(Key={"source_id": "nvd"})["Item"]
    assert item["consecutive_failures"] == 0


def test_nvd_handler_defaults_lookback_when_no_state(polling_table, monkeypatch):
    monkeypatch.setenv("POLLING_STATE_TABLE_NAME", "crossroads-test-pollingstate")
    seen = {}
    monkeypatch.setattr(
        nvd, "poll_nvd_delta",
        lambda d, h, lsa: (seen.setdefault("lsa", lsa) and 0, "2026-07-23T00:00:00+00:00"),
    )
    nvd.handler({}, None, driver=_FakeDriver(), http_client=object())
    # A default ISO timestamp (not None) was synthesized for the first-run window.
    assert seen["lsa"].endswith("+00:00")


def test_nvd_handler_records_failure_and_reraises(polling_table, monkeypatch):
    monkeypatch.setenv("POLLING_STATE_TABLE_NAME", "crossroads-test-pollingstate")

    def boom(*a, **k):
        raise RuntimeError("nvd down")

    monkeypatch.setattr(nvd, "poll_nvd_delta", boom)
    with pytest.raises(RuntimeError):
        nvd.handler({}, None, driver=_FakeDriver(), http_client=object())
    item = polling_table.get_item(Key={"source_id": "nvd"})["Item"]
    assert item["consecutive_failures"] == 1


class _NoopSession:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute_write(self, *a, **k):  # never reached when the NVD body is empty
        raise AssertionError("no CVEs to write")


class _SessionDriver:
    """A driver whose empty-body poll never dereferences a session body."""

    def session(self):
        return _NoopSession()


class _CapturingHttp:
    def __init__(self, body):
        self._body = body
        self.calls: list[dict] = []

    def get(self, url, params=None):
        self.calls.append({"url": url, "params": params or {}})
        return _NvdResponse(self._body)


class _NvdResponse:
    def __init__(self, body):
        self._body = body
        self.status_code = 200
        self.headers: dict = {}

    def json(self):
        return self._body


def test_nvd_handler_records_the_fetch_window_end_not_a_later_now(polling_table, monkeypatch):
    """Regression (Important): the delta poll's `lastModEndDate` (its fetch-window end) and
    the `last_success_at` recorded for the next poll's window start must be ONE captured
    instant, not two independent `now()` calls. Two `now()`s leave a gap in which a CVE
    modified once and not again is silently never re-polled. Assert the recorded
    last_success_at equals the exact lastModEndDate sent to NVD.
    """
    monkeypatch.setenv("POLLING_STATE_TABLE_NAME", "crossroads-test-pollingstate")
    polling_table.put_item(
        Item={"source_id": "nvd", "last_success_at": "2026-07-01T00:00:00+00:00"}
    )

    http = _CapturingHttp({"version": "2.0", "vulnerabilities": []})
    nvd.handler({}, None, driver=_SessionDriver(), http_client=http)

    window_end = http.calls[0]["params"]["lastModEndDate"]
    item = polling_table.get_item(Key={"source_id": "nvd"})["Item"]
    assert item["last_success_at"] == window_end


def test_cisa_handler_passes_one_client_for_both_seams(monkeypatch):
    seen = {}
    monkeypatch.setattr(
        cisa_kev,
        "process_cisa_kev",
        lambda driver, http, nvd_http: seen.update(same=http is nvd_http) or 2,
    )
    client = object()
    result = cisa_kev.handler(driver=_FakeDriver(), http_client=client)
    assert result == {"cves_created": 2}
    assert seen["same"] is True


def test_ghsa_handler_resolves_topic_arn_and_calls_process(monkeypatch):
    from src.common.config import get_config

    monkeypatch.setenv("CROSSROADS_GRAPH_WRITES_TOPIC_ARN", "arn:aws:sns:us-east-1:1:graph-writes")
    get_config.cache_clear()  # get_config is lru_cached; a prior test may have cached this key
    seen = {}

    def fake_process(driver, http, nvd_http, *, sns_client, topic_arn):
        seen["topic_arn"] = topic_arn
        return 1

    monkeypatch.setattr(ghsa, "process_ghsa", fake_process)
    result = ghsa.handler(driver=_FakeDriver(), http_client=object(), sns_client=object())
    assert result == {"cves_created": 1}
    assert seen["topic_arn"] == "arn:aws:sns:us-east-1:1:graph-writes"


def test_otx_handler_passes_a_now_clock(monkeypatch):
    seen = {}

    def fake_process(driver, http, nvd_http, *, now):
        seen["now"] = now
        return 0

    monkeypatch.setattr(otx, "process_otx", fake_process)
    otx.handler(driver=_FakeDriver(), http_client=object())
    assert seen["now"] is not None


def test_abusech_three_handlers_call_their_own_process_fns(monkeypatch):
    calls = []
    monkeypatch.setattr(abusech, "process_urlhaus", lambda d, h: calls.append("urlhaus") or 1)
    monkeypatch.setattr(abusech, "process_malwarebazaar", lambda d, h: calls.append("mb") or 2)
    monkeypatch.setattr(abusech, "process_threatfox", lambda d, h, *, now: calls.append("tf") or 3)

    assert abusech.urlhaus_handler(driver=_FakeDriver(), http_client=object()) == {"iocs_processed": 1}
    assert abusech.malwarebazaar_handler(driver=_FakeDriver(), http_client=object()) == {"iocs_processed": 2}
    assert abusech.threatfox_handler(driver=_FakeDriver(), http_client=object()) == {"iocs_processed": 3}
    assert calls == ["urlhaus", "mb", "tf"]


def test_epss_handler_passes_injected_fetch_fn(monkeypatch):
    seen = {}
    monkeypatch.setattr(
        epss, "refresh_epss_scores", lambda driver, fetch: seen.update(fetch=fetch) or 9
    )
    fetch = lambda: "cve,epss\nCVE-1,0.5\n"  # noqa: E731
    result = epss.handler(driver=_FakeDriver(), fetch_epss_file_fn=fetch)
    assert result == {"cves_updated": 9}
    assert seen["fetch"] is fetch


def test_attck_handler_reads_and_persists_versions(polling_table, monkeypatch):
    monkeypatch.setenv("POLLING_STATE_TABLE_NAME", "crossroads-test-pollingstate")
    polling_table.put_item(
        Item={"source_id": "mitre_attck", "last_ingested_versions": {"enterprise-attack": "16.0"}}
    )
    seen = {}

    def fake_sync(driver, fidx, fbundle, last_versions):
        seen["last_versions"] = dict(last_versions)  # snapshot before the handler merges
        return {"enterprise-attack": "17.0"}

    monkeypatch.setattr(attck_sync, "sync_attck", fake_sync)
    result = attck_sync.handler(
        driver=_FakeDriver(),
        fetch_index_fn=lambda d: {"version": "17.0"},
        fetch_bundle_fn=lambda d: {},
    )
    assert result == {"domains_ingested": {"enterprise-attack": "17.0"}}
    assert seen["last_versions"] == {"enterprise-attack": "16.0"}
    # The merged versions are persisted back for the next run.
    item = polling_table.get_item(Key={"source_id": "mitre_attck"})["Item"]
    assert item["last_ingested_versions"]["enterprise-attack"] == "17.0"


def test_attck_github_fetchers_map_domain_to_latest_version():
    """The default GitHub index adapter picks the newest version for a domain's
    collection and shapes it into the module's `{"version": ...}` contract."""

    class FakeResp:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            pass

        def json(self):
            return self._payload

    index_payload = {
        "collections": [
            {
                "name": "Enterprise ATT&CK",
                "versions": [{"version": "16.1"}, {"version": "17.0"}, {"version": "9.0"}],
            }
        ]
    }

    class FakeClient:
        def get(self, url, timeout=None):
            return FakeResp(index_payload)

    fetch_index_fn, _ = attck_sync._make_github_fetchers(FakeClient())
    assert fetch_index_fn("enterprise-attack") == {"version": "17.0"}
    assert fetch_index_fn("ics-attack") == {"version": ""}  # not in this index
