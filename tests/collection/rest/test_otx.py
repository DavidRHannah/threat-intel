"""Integration tests for the OTX normalizer (L1 Task 9).

Runs against a real local Neo4j (docker compose up -d neo4j) and a moto-mocked SNS
topic (real `boto3` calls, no live AWS) for the `publish_graph_write` edge announcement.

- FR-DC-22: a pulse's CVE-type indicator gets a lazy stub + on-demand NVD enrichment.
- FR-DC-01: non-CVE indicators MERGE an IOC keyed on the synthetic `value_type_key`.
- INDICATES edges (IOC->CVE) are written via `upsert_authoritative_assertion` inside
  `session.execute_write` and announced via `publish_graph_write` (edge-shaped).
- Credentials load via `load_credential`, never hardcoded.
- FR-DC-19/20/21 (via Task 7): 401/429/5xx/malformed all route through `handle_response`.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from src.collection.rest.http_errors import NoRetryError, RetryableError, RetryAfterError
from src.collection.rest.otx import OtxNormalizer, process_otx
from src.common import config, natural_keys
from src.common.neo4j_driver import close_driver, get_driver
from src.common.schema_bootstrap import bootstrap_schema

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


class FakeResponse:
    def __init__(self, body, status_code: int = 200, headers: dict | None = None):
        self._body = body
        self.status_code = status_code
        self.headers = headers or {}

    def json(self):
        return self._body


class FakeHttpClient:
    def __init__(self, response: FakeResponse):
        self._response = response
        self.calls: list[dict] = []

    def get(self, url, params=None, headers=None):
        self.calls.append({"url": url, "params": params or {}, "headers": headers or {}})
        return self._response


class FakeNvdHttpClient:
    def __init__(self, response: FakeResponse):
        self._response = response
        self.calls: list[dict] = []

    def get(self, url, params=None):
        self.calls.append({"url": url, "params": params or {}})
        return self._response


@pytest.fixture(autouse=True)
def _clear_config_cache(monkeypatch):
    config.get_config.cache_clear()
    monkeypatch.delenv("CROSSROADS_ENV", raising=False)
    monkeypatch.setenv("CROSSROADS_OTX_API_KEY", "test-otx-key")
    yield
    config.get_config.cache_clear()


@pytest.fixture
def driver():
    d = get_driver()
    d.verify_connectivity()
    bootstrap_schema(d)
    ioc_keys = [
        natural_keys.ioc_key("198.51.100.23", "ip"),
        natural_keys.ioc_key("evil-c2.example.net", "domain"),
    ]
    with d.session() as s:
        s.run(
            "MATCH (n) WHERE n.test_fixture = true "
            "OR (n:CVE AND n.cve_id = 'CVE-2026-2002') "
            "OR (n:IOC AND n.value_type_key IN $keys) "
            "DETACH DELETE n",
            keys=ioc_keys,
        ).consume()
        s.run("MERGE (w:CWE {cwe_id:'CWE-502'})").consume()
    yield d
    with d.session() as s:
        s.run(
            "MATCH (n) WHERE n.test_fixture = true "
            "OR (n:CVE AND n.cve_id = 'CVE-2026-2002') "
            "OR (n:IOC AND n.value_type_key IN $keys) "
            "DETACH DELETE n",
            keys=ioc_keys,
        ).consume()
    close_driver()


def _ioc_props(driver, value: str, ioc_type: str) -> dict | None:
    key = natural_keys.ioc_key(value, ioc_type)
    with driver.session() as s:
        rec = s.run("MATCH (i:IOC {value_type_key:$key}) RETURN i", key=key).single()
    return dict(rec["i"]) if rec else None


def _cve_props(driver, cve_id: str) -> dict | None:
    with driver.session() as s:
        rec = s.run("MATCH (c:CVE {cve_id:$id}) RETURN c", id=cve_id).single()
    return dict(rec["c"]) if rec else None


def _indicates_edges(driver, cve_id: str) -> list[dict]:
    with driver.session() as s:
        rows = s.run(
            "MATCH (i:IOC)-[r:INDICATES]->(:CVE {cve_id:$id}) RETURN i.value AS value, r",
            id=cve_id,
        )
        return [{"value": row["value"], **dict(row["r"])} for row in rows]


@pytest.fixture
def aws(monkeypatch):
    with mock_aws():
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
        sns = boto3.client("sns", region_name="us-east-1")
        topic_arn = sns.create_topic(Name="graph-writes")["TopicArn"]
        monkeypatch.setenv("CROSSROADS_GRAPH_WRITES_TOPIC_ARN", topic_arn)
        config.get_config.cache_clear()

        sqs = boto3.client("sqs", region_name="us-east-1")
        queue_url = sqs.create_queue(QueueName="probe")["QueueUrl"]
        queue_arn = sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)
        yield {"sqs": sqs, "queue_url": queue_url}
        config.get_config.cache_clear()


# --- Unit: normalizer parses the fixture shape ----------------------------------


def test_normalizer_parses_fixture_shape():
    parsed = OtxNormalizer().parse(_load("otx_pulses.json"))
    assert len(parsed) == 1
    pulse = parsed[0]
    assert pulse.cve_ids == ["CVE-2026-2002"]
    assert ("198.51.100.23", "ip") in pulse.ioc_values
    assert ("evil-c2.example.net", "domain") in pulse.ioc_values


def test_normalize_returns_ioc_and_cve_upserts():
    upserts = OtxNormalizer().normalize(_load("otx_pulses.json"))
    ioc_upserts = [u for u in upserts if u.label == "IOC"]
    cve_upserts = [u for u in upserts if u.label == "CVE"]
    assert len(ioc_upserts) == 2
    assert {u.natural_key["cve_id"] for u in cve_upserts} == {"CVE-2026-2002"}
    expected_key = natural_keys.ioc_key("198.51.100.23", "ip")
    assert any(u.natural_key["value_type_key"] == expected_key for u in ioc_upserts)


# --- FR-DC-22 / FR-DC-01 / INDICATES edge ---------------------------------------


def test_pulse_merges_iocs_lazy_cve_and_indicates_edges(driver, aws):
    otx_client = FakeHttpClient(FakeResponse(_load("otx_pulses.json")))
    nvd_client = FakeNvdHttpClient(FakeResponse(_load("nvd_single_cve.json")))
    now = datetime(2026, 7, 22, tzinfo=timezone.utc)

    created_count = process_otx(driver, otx_client, nvd_client, now=now)

    assert created_count == 1  # CVE-2026-2002 was unseen

    ip_ioc = _ioc_props(driver, "198.51.100.23", "ip")
    assert ip_ioc["value"] == "198.51.100.23"
    domain_ioc = _ioc_props(driver, "evil-c2.example.net", "domain")
    assert domain_ioc["ioc_type"] == "domain"

    cve = _cve_props(driver, "CVE-2026-2002")
    assert cve["cvss_score"] == 9.8  # NVD enrichment landed on the stub

    edges = _indicates_edges(driver, "CVE-2026-2002")
    assert {e["value"] for e in edges} == {"198.51.100.23", "evil-c2.example.net"}
    for e in edges:
        assert "authoritative" in e["origin"]
        assert e["feed_sources"] == ["otx"]

    # publish_graph_write announced both edges (edge-shaped, via SQS subscribed to the
    # moto-mocked graph-writes SNS topic).
    messages = aws["sqs"].receive_message(QueueUrl=aws["queue_url"], MaxNumberOfMessages=10).get(
        "Messages", []
    )
    bodies = [json.loads(json.loads(m["Body"])["Message"]) for m in messages]
    assert len(bodies) == 2
    assert all(b["rel_type"] == "INDICATES" for b in bodies)


def test_credential_loaded_via_load_credential_never_hardcoded(driver, aws):
    otx_client = FakeHttpClient(FakeResponse(_load("otx_pulses.json")))
    nvd_client = FakeNvdHttpClient(FakeResponse(_load("nvd_single_cve.json")))
    now = datetime(2026, 7, 22, tzinfo=timezone.utc)

    process_otx(driver, otx_client, nvd_client, now=now)

    assert otx_client.calls[0]["headers"]["X-OTX-API-KEY"] == "test-otx-key"


# --- FR-DC-19/20/21 (via Task 7): handle_response routing -----------------------


def test_401_routes_through_handle_response(driver):
    otx_client = FakeHttpClient(FakeResponse({}, status_code=401))
    nvd_client = FakeNvdHttpClient(FakeResponse({}))
    with pytest.raises(NoRetryError):
        process_otx(driver, otx_client, nvd_client, now=datetime.now(timezone.utc))


def test_429_routes_through_handle_response(driver):
    otx_client = FakeHttpClient(
        FakeResponse({}, status_code=429, headers={"Retry-After": "30"})
    )
    nvd_client = FakeNvdHttpClient(FakeResponse({}))
    with pytest.raises(RetryAfterError) as exc_info:
        process_otx(driver, otx_client, nvd_client, now=datetime.now(timezone.utc))
    assert exc_info.value.retry_after_seconds == 30


def test_5xx_routes_through_handle_response(driver):
    otx_client = FakeHttpClient(FakeResponse({}, status_code=503))
    nvd_client = FakeNvdHttpClient(FakeResponse({}))
    with pytest.raises(RetryableError):
        process_otx(driver, otx_client, nvd_client, now=datetime.now(timezone.utc))


def test_malformed_body_routes_through_handle_response(driver):
    otx_client = FakeHttpClient(FakeResponse({"unexpected": "shape"}, status_code=200))
    nvd_client = FakeNvdHttpClient(FakeResponse({}))
    with pytest.raises(NoRetryError):
        process_otx(driver, otx_client, nvd_client, now=datetime.now(timezone.utc))
