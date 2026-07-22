"""Integration tests for the abuse.ch normalizers (URLhaus/MalwareBazaar/ThreatFox, L1
Task 9). One test class per feed, per the plan's "three independent normalizers, not a
unified client" scope.

Runs against a real local Neo4j (docker compose up -d neo4j) and, for ThreatFox's edge
announcement, a moto-mocked SNS topic.

- FR-DC-01: each feed MERGEs a plain IOC keyed on the synthetic `value_type_key`; ThreatFox
  additionally MERGEs a `MalwareFamily` and writes the implied `MalwareFamily->IOC` edge
  (`HAS_SAMPLE` for its hash record, `COMMUNICATES_WITH` for its network record) via
  `upsert_authoritative_assertion`, announced via `publish_graph_write`.
- Credentials load via `load_credential` (an `Auth-Key` header), never hardcoded.
- FR-DC-19/20/21 (via Task 7): 401/429/5xx/malformed all route through `handle_response`,
  one assertion per feed.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from src.collection.rest.abusech import (
    MalwareBazaarNormalizer,
    ThreatFoxNormalizer,
    UrlhausNormalizer,
    process_malwarebazaar,
    process_threatfox,
    process_urlhaus,
)
from src.collection.rest.http_errors import NoRetryError, RetryableError, RetryAfterError
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
        self.calls.append({"method": "get", "url": url, "params": params or {}, "headers": headers or {}})
        return self._response

    def post(self, url, data=None, headers=None):
        self.calls.append({"method": "post", "url": url, "data": data or {}, "headers": headers or {}})
        return self._response


@pytest.fixture(autouse=True)
def _clear_config_cache(monkeypatch):
    config.get_config.cache_clear()
    monkeypatch.delenv("CROSSROADS_ENV", raising=False)
    monkeypatch.setenv("CROSSROADS_URLHAUS_API_KEY", "test-urlhaus-key")
    monkeypatch.setenv("CROSSROADS_MALWAREBAZAAR_API_KEY", "test-malwarebazaar-key")
    monkeypatch.setenv("CROSSROADS_THREATFOX_API_KEY", "test-threatfox-key")
    yield
    config.get_config.cache_clear()


@pytest.fixture
def driver():
    d = get_driver()
    d.verify_connectivity()
    bootstrap_schema(d)
    ioc_keys = [
        natural_keys.ioc_key("http://evil-drop.example/payload.exe", "url"),
        natural_keys.ioc_key(
            "3f786850e387550fdab836ed7e6dc881de23001b", "sha256_hash"
        ),
        natural_keys.ioc_key("185.220.101.5:443", "ip:port"),
        natural_keys.ioc_key(
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "sha256_hash",
        ),
    ]
    with d.session() as s:
        s.run(
            "MATCH (n) WHERE n.test_fixture = true "
            "OR (n:IOC AND n.value_type_key IN $keys) "
            "OR (n:MalwareFamily AND n.merge_key = 'emotet') "
            "OR (n:Source AND n.source_id = 'threatfox') "
            "DETACH DELETE n",
            keys=ioc_keys,
        ).consume()
    yield d
    with d.session() as s:
        s.run(
            "MATCH (n) WHERE n.test_fixture = true "
            "OR (n:IOC AND n.value_type_key IN $keys) "
            "OR (n:MalwareFamily AND n.merge_key = 'emotet') "
            "OR (n:Source AND n.source_id = 'threatfox') "
            "DETACH DELETE n",
            keys=ioc_keys,
        ).consume()
    close_driver()


def _seed_source_credibility(driver, source_id: str, credibility_score: float) -> None:
    with driver.session() as s:
        s.run(
            "MERGE (s:Source {source_id: $source_id}) "
            "SET s.credibility_score = $score, s.test_fixture = true",
            source_id=source_id,
            score=credibility_score,
        ).consume()


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


def _ioc_props(driver, value: str, ioc_type: str) -> dict | None:
    key = natural_keys.ioc_key(value, ioc_type)
    with driver.session() as s:
        rec = s.run("MATCH (i:IOC {value_type_key:$key}) RETURN i", key=key).single()
    return dict(rec["i"]) if rec else None


# =================================================================================
# URLhaus
# =================================================================================


class TestUrlhaus:
    def test_normalizer_parses_fixture_shape(self):
        parsed = UrlhausNormalizer().parse(_load("urlhaus_recent.json"))
        assert len(parsed) == 1
        assert parsed[0].value == "http://evil-drop.example/payload.exe"
        assert parsed[0].ioc_type == "url"
        assert parsed[0].properties["threat"] == "malware_download"

    def test_normalize_returns_ioc_upserts(self):
        upserts = UrlhausNormalizer().normalize(_load("urlhaus_recent.json"))
        assert len(upserts) == 1
        assert upserts[0].label == "IOC"
        assert upserts[0].natural_key["value_type_key"] == natural_keys.ioc_key(
            "http://evil-drop.example/payload.exe", "url"
        )

    def test_merges_ioc_on_synthetic_key(self, driver):
        client = FakeHttpClient(FakeResponse(_load("urlhaus_recent.json")))
        count = process_urlhaus(driver, client)
        assert count == 1
        ioc = _ioc_props(driver, "http://evil-drop.example/payload.exe", "url")
        assert ioc["ioc_type"] == "url"
        assert ioc["host"] == "evil-drop.example"

    def test_credential_loaded_via_load_credential(self, driver):
        client = FakeHttpClient(FakeResponse(_load("urlhaus_recent.json")))
        process_urlhaus(driver, client)
        assert client.calls[0]["headers"]["Auth-Key"] == "test-urlhaus-key"

    def test_401_routes_through_handle_response(self, driver):
        client = FakeHttpClient(FakeResponse({}, status_code=401))
        with pytest.raises(NoRetryError):
            process_urlhaus(driver, client)

    def test_429_routes_through_handle_response(self, driver):
        client = FakeHttpClient(FakeResponse({}, status_code=429, headers={"Retry-After": "30"}))
        with pytest.raises(RetryAfterError) as exc_info:
            process_urlhaus(driver, client)
        assert exc_info.value.retry_after_seconds == 30

    def test_5xx_routes_through_handle_response(self, driver):
        client = FakeHttpClient(FakeResponse({}, status_code=503))
        with pytest.raises(RetryableError):
            process_urlhaus(driver, client)

    def test_malformed_body_routes_through_handle_response(self, driver):
        client = FakeHttpClient(FakeResponse({"query_status": "no_results"}, status_code=200))
        with pytest.raises(NoRetryError):
            process_urlhaus(driver, client)


# =================================================================================
# MalwareBazaar
# =================================================================================


class TestMalwareBazaar:
    def test_normalizer_parses_fixture_shape(self):
        parsed = MalwareBazaarNormalizer().parse(_load("malwarebazaar_recent.json"))
        assert len(parsed) == 1
        assert parsed[0].value == "3f786850e387550fdab836ed7e6dc881de23001b"
        assert parsed[0].ioc_type == "sha256_hash"
        assert parsed[0].properties["signature"] == "AgentTesla"

    def test_normalize_returns_ioc_upserts(self):
        upserts = MalwareBazaarNormalizer().normalize(_load("malwarebazaar_recent.json"))
        assert len(upserts) == 1
        assert upserts[0].label == "IOC"

    def test_merges_ioc_on_synthetic_key(self, driver):
        client = FakeHttpClient(FakeResponse(_load("malwarebazaar_recent.json")))
        count = process_malwarebazaar(driver, client)
        assert count == 1
        ioc = _ioc_props(driver, "3f786850e387550fdab836ed7e6dc881de23001b", "sha256_hash")
        assert ioc["signature"] == "AgentTesla"

    def test_credential_loaded_via_load_credential(self, driver):
        client = FakeHttpClient(FakeResponse(_load("malwarebazaar_recent.json")))
        process_malwarebazaar(driver, client)
        assert client.calls[0]["headers"]["Auth-Key"] == "test-malwarebazaar-key"

    def test_401_routes_through_handle_response(self, driver):
        client = FakeHttpClient(FakeResponse({}, status_code=401))
        with pytest.raises(NoRetryError):
            process_malwarebazaar(driver, client)

    def test_429_routes_through_handle_response(self, driver):
        client = FakeHttpClient(FakeResponse({}, status_code=429, headers={"Retry-After": "30"}))
        with pytest.raises(RetryAfterError) as exc_info:
            process_malwarebazaar(driver, client)
        assert exc_info.value.retry_after_seconds == 30

    def test_5xx_routes_through_handle_response(self, driver):
        client = FakeHttpClient(FakeResponse({}, status_code=503))
        with pytest.raises(RetryableError):
            process_malwarebazaar(driver, client)

    def test_malformed_body_routes_through_handle_response(self, driver):
        client = FakeHttpClient(FakeResponse({"query_status": "no_results"}, status_code=200))
        with pytest.raises(NoRetryError):
            process_malwarebazaar(driver, client)


# =================================================================================
# ThreatFox
# =================================================================================


class TestThreatFox:
    def test_normalizer_parses_fixture_shape(self):
        parsed = ThreatFoxNormalizer().parse(_load("threatfox_recent.json"))
        assert len(parsed) == 2
        network, sample = parsed
        assert network.ioc_type == "ip:port"
        assert network.rel_type == "COMMUNICATES_WITH"
        assert sample.ioc_type == "sha256_hash"
        assert sample.rel_type == "HAS_SAMPLE"
        assert network.malware_merge_key == "emotet"

    def test_normalize_returns_ioc_and_malware_family_upserts(self):
        upserts = ThreatFoxNormalizer().normalize(_load("threatfox_recent.json"))
        assert {u.label for u in upserts} == {"IOC", "MalwareFamily"}
        family_upserts = [u for u in upserts if u.label == "MalwareFamily"]
        assert all(u.natural_key["merge_key"] == "emotet" for u in family_upserts)

    def test_merges_iocs_family_and_edges(self, driver, aws):
        _seed_source_credibility(driver, "threatfox", 0.63)
        client = FakeHttpClient(FakeResponse(_load("threatfox_recent.json")))
        now = datetime(2026, 7, 22, tzinfo=timezone.utc)

        count = process_threatfox(driver, client, now=now)
        assert count == 2

        network_ioc = _ioc_props(driver, "185.220.101.5:443", "ip:port")
        assert network_ioc["threat_type"] == "botnet_cc"
        sample_ioc = _ioc_props(
            driver,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "sha256_hash",
        )
        assert sample_ioc["threat_type"] == "payload"

        with driver.session() as s:
            family = s.run(
                "MATCH (m:MalwareFamily {merge_key:'emotet'}) RETURN m"
            ).single()
        assert dict(family["m"])["name"] == "Emotet"

        with driver.session() as s:
            comm = s.run(
                "MATCH (:MalwareFamily {merge_key:'emotet'})-[r:COMMUNICATES_WITH]->"
                "(:IOC {value_type_key:$k}) RETURN r",
                k=natural_keys.ioc_key("185.220.101.5:443", "ip:port"),
            ).single()
            sample_edge = s.run(
                "MATCH (:MalwareFamily {merge_key:'emotet'})-[r:HAS_SAMPLE]->"
                "(:IOC {value_type_key:$k}) RETURN r",
                k=natural_keys.ioc_key(
                    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                    "sha256_hash",
                ),
            ).single()
        assert comm is not None
        assert sample_edge is not None
        assert "authoritative" in dict(comm["r"])["origin"]
        # Source.credibility_score (seeded above) flows through as authoritative_confidence,
        # not the old hardcoded ABUSECH_CREDIBILITY_SCORE placeholder.
        assert dict(comm["r"])["authoritative_confidence"] == 0.63
        assert dict(sample_edge["r"])["authoritative_confidence"] == 0.63

        messages = aws["sqs"].receive_message(
            QueueUrl=aws["queue_url"], MaxNumberOfMessages=10
        ).get("Messages", [])
        bodies = [json.loads(json.loads(m["Body"])["Message"]) for m in messages]
        assert {b["rel_type"] for b in bodies} == {"COMMUNICATES_WITH", "HAS_SAMPLE"}

    def test_credential_loaded_via_load_credential(self, driver, aws):
        client = FakeHttpClient(FakeResponse(_load("threatfox_recent.json")))
        process_threatfox(driver, client, now=datetime.now(timezone.utc))
        assert client.calls[0]["headers"]["Auth-Key"] == "test-threatfox-key"

    def test_missing_source_falls_back_to_default_credibility(self, driver, aws):
        # No Source node seeded at all -- must fall back rather than raise or block the write.
        client = FakeHttpClient(FakeResponse(_load("threatfox_recent.json")))
        process_threatfox(driver, client, now=datetime.now(timezone.utc))

        with driver.session() as s:
            comm = s.run(
                "MATCH (:MalwareFamily {merge_key:'emotet'})-[r:COMMUNICATES_WITH]->"
                "(:IOC {value_type_key:$k}) RETURN r",
                k=natural_keys.ioc_key("185.220.101.5:443", "ip:port"),
            ).single()
        assert dict(comm["r"])["authoritative_confidence"] == 0.5  # documented default

    def test_401_routes_through_handle_response(self, driver):
        client = FakeHttpClient(FakeResponse({}, status_code=401))
        with pytest.raises(NoRetryError):
            process_threatfox(driver, client, now=datetime.now(timezone.utc))

    def test_429_routes_through_handle_response(self, driver):
        client = FakeHttpClient(FakeResponse({}, status_code=429, headers={"Retry-After": "30"}))
        with pytest.raises(RetryAfterError) as exc_info:
            process_threatfox(driver, client, now=datetime.now(timezone.utc))
        assert exc_info.value.retry_after_seconds == 30

    def test_5xx_routes_through_handle_response(self, driver):
        client = FakeHttpClient(FakeResponse({}, status_code=503))
        with pytest.raises(RetryableError):
            process_threatfox(driver, client, now=datetime.now(timezone.utc))

    def test_malformed_body_routes_through_handle_response(self, driver):
        client = FakeHttpClient(FakeResponse({"query_status": "no_results"}, status_code=200))
        with pytest.raises(NoRetryError):
            process_threatfox(driver, client, now=datetime.now(timezone.utc))
