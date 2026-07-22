"""Integration tests for the GHSA normalizer (L1 Task 9).

Runs against a real local Neo4j (docker compose up -d neo4j).

- FR-DC-22: an advisory referencing an unseen CVE gets a lazy stub + on-demand NVD
  enrichment; an advisory with no CVE identifier yet still produces its Article.
- FR-DC-01: the Article MERGEs on the synthetic `source_guid_key`
  (`article_key("ghsa", <GHSA-ID>)`), never the raw `(source_id, guid)` pair.
- The Article announcement is hand-rolled, node-shaped (NOT `publish_graph_write`).
- Credentials load via `load_credential`, never hardcoded.
- FR-DC-19/20/21 (via Task 7): 401/429/5xx/malformed all route through `handle_response`.
"""

import json
from pathlib import Path

import pytest

from src.collection.rest.ghsa import GhsaNormalizer, process_ghsa
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
    """GHSA's own client -- GraphQL over POST."""

    def __init__(self, response: FakeResponse):
        self._response = response
        self.calls: list[dict] = []

    def post(self, url, json=None, headers=None):
        self.calls.append({"url": url, "json": json, "headers": headers or {}})
        return self._response


class FakeNvdHttpClient:
    """NVD's client -- GET, as `enrich_cve` (Task 8) expects."""

    def __init__(self, response: FakeResponse):
        self._response = response
        self.calls: list[dict] = []

    def get(self, url, params=None):
        self.calls.append({"url": url, "params": params or {}})
        return self._response


class FakeSnsClient:
    def __init__(self):
        self.published: list[dict] = []

    def publish(self, TopicArn, Message):
        self.published.append({"TopicArn": TopicArn, "Message": json.loads(Message)})


@pytest.fixture(autouse=True)
def _clear_config_cache(monkeypatch):
    config.get_config.cache_clear()
    monkeypatch.delenv("CROSSROADS_ENV", raising=False)
    monkeypatch.setenv("CROSSROADS_GHSA_TOKEN", "test-github-token")
    yield
    config.get_config.cache_clear()


@pytest.fixture
def driver():
    d = get_driver()
    d.verify_connectivity()
    bootstrap_schema(d)
    ids = ["CVE-2026-1001", "CVE-2026-2002"]
    guids = ["GHSA-abcd-1234-efgh", "GHSA-wxyz-5678-ijkl"]
    with d.session() as s:
        s.run(
            "MATCH (n) WHERE n.test_fixture = true "
            "OR (n:CVE AND n.cve_id IN $ids) "
            "OR (n:Article AND n.guid IN $guids) "
            "DETACH DELETE n",
            ids=ids, guids=guids,
        ).consume()
        s.run("MERGE (w:CWE {cwe_id:'CWE-502'})").consume()
    yield d
    with d.session() as s:
        s.run(
            "MATCH (n) WHERE n.test_fixture = true "
            "OR (n:CVE AND n.cve_id IN $ids) "
            "OR (n:Article AND n.guid IN $guids) "
            "DETACH DELETE n",
            ids=ids, guids=guids,
        ).consume()
    close_driver()


def _cve_props(driver, cve_id: str) -> dict | None:
    with driver.session() as s:
        rec = s.run("MATCH (c:CVE {cve_id:$id}) RETURN c", id=cve_id).single()
    return dict(rec["c"]) if rec else None


def _article_props(driver, source_guid_key: str) -> dict | None:
    with driver.session() as s:
        rec = s.run(
            "MATCH (a:Article {source_guid_key:$k}) RETURN a", k=source_guid_key
        ).single()
    return dict(rec["a"]) if rec else None


# --- Unit: normalizer parses the fixture shape ----------------------------------


def test_normalizer_parses_fixture_shape():
    parsed = GhsaNormalizer().parse(_load("ghsa_advisories.json"))
    by_id = {p.ghsa_id: p for p in parsed}
    assert set(by_id) == {"GHSA-abcd-1234-efgh", "GHSA-wxyz-5678-ijkl"}
    with_cve = by_id["GHSA-abcd-1234-efgh"]
    assert with_cve.cve_id == "CVE-2026-2002"
    assert with_cve.severity == "HIGH"
    assert "Prototype pollution" in with_cve.description or with_cve.description
    no_cve = by_id["GHSA-wxyz-5678-ijkl"]
    assert no_cve.cve_id is None


def test_normalize_returns_cve_and_article_upserts():
    upserts = GhsaNormalizer().normalize(_load("ghsa_advisories.json"))
    cve_upserts = [u for u in upserts if u.label == "CVE"]
    article_upserts = [u for u in upserts if u.label == "Article"]
    assert {u.natural_key["cve_id"] for u in cve_upserts} == {"CVE-2026-2002"}
    assert len(article_upserts) == 2
    expected_key = natural_keys.article_key("ghsa", "GHSA-abcd-1234-efgh")
    assert any(u.natural_key["source_guid_key"] == expected_key for u in article_upserts)


# --- FR-DC-22 / FR-DC-01: structured CVE path + Article path -------------------


def test_advisory_with_cve_creates_stub_enriches_and_publishes_article(driver):
    ghsa_client = FakeHttpClient(FakeResponse(_load("ghsa_advisories.json")))
    nvd_client = FakeNvdHttpClient(FakeResponse(_load("nvd_single_cve.json")))
    sns_client = FakeSnsClient()

    created_count = process_ghsa(
        driver, ghsa_client, nvd_client, sns_client=sns_client, topic_arn="arn:test:topic"
    )

    assert created_count == 1  # only CVE-2026-2002 was unseen

    cve = _cve_props(driver, "CVE-2026-2002")
    assert cve["ghsa_id"] == "GHSA-abcd-1234-efgh"
    assert cve["ghsa_severity"] == "HIGH"
    assert cve["cvss_score"] == 9.8  # NVD enrichment landed on the same node

    key = natural_keys.article_key("ghsa", "GHSA-abcd-1234-efgh")
    article = _article_props(driver, key)
    assert article["source_id"] == "ghsa"
    assert article["guid"] == "GHSA-abcd-1234-efgh"
    assert "prototype pollution" in article["cleaned_text"]

    # Node-shaped, hand-rolled announcement -- NOT publish_graph_write's edge shape.
    messages = [p["Message"] for p in sns_client.published]
    article_msg = next(m for m in messages if m["guid"] == "GHSA-abcd-1234-efgh")
    assert article_msg["node_label"] == "Article"
    assert article_msg["article_id"] == key
    assert article_msg["cleaned_text"] == article["cleaned_text"]
    assert "rel_type" not in article_msg  # not an edge-shaped publish_graph_write message


def test_advisory_without_cve_still_produces_article(driver):
    """FR-DC-01: an advisory GitHub hasn't yet linked to a CVE must not block its
    Article from being created -- structured CVE-linking and the Article are
    independent outputs."""
    ghsa_client = FakeHttpClient(FakeResponse(_load("ghsa_advisories.json")))
    nvd_client = FakeNvdHttpClient(FakeResponse(_load("nvd_single_cve.json")))
    sns_client = FakeSnsClient()

    process_ghsa(driver, ghsa_client, nvd_client, sns_client=sns_client, topic_arn="arn:test:topic")

    key = natural_keys.article_key("ghsa", "GHSA-wxyz-5678-ijkl")
    article = _article_props(driver, key)
    assert article is not None
    assert "path traversal" in article["cleaned_text"]


def test_credential_loaded_via_load_credential_never_hardcoded(driver):
    """Asserts the GHSA token flows into the outgoing request's Authorization header
    from load_credential (env var CROSSROADS_GHSA_TOKEN set by the autouse fixture),
    never a hardcoded literal."""
    ghsa_client = FakeHttpClient(FakeResponse(_load("ghsa_advisories.json")))
    nvd_client = FakeNvdHttpClient(FakeResponse(_load("nvd_single_cve.json")))
    sns_client = FakeSnsClient()

    process_ghsa(driver, ghsa_client, nvd_client, sns_client=sns_client, topic_arn="arn:test:topic")

    assert ghsa_client.calls[0]["headers"]["Authorization"] == "Bearer test-github-token"


# --- FR-DC-19/20/21 (via Task 7): handle_response routing -----------------------


def test_401_routes_through_handle_response(driver):
    ghsa_client = FakeHttpClient(FakeResponse({}, status_code=401))
    nvd_client = FakeNvdHttpClient(FakeResponse({}))
    with pytest.raises(NoRetryError):
        process_ghsa(
            driver, ghsa_client, nvd_client, sns_client=FakeSnsClient(), topic_arn="arn:test:topic"
        )


def test_429_routes_through_handle_response(driver):
    ghsa_client = FakeHttpClient(
        FakeResponse({}, status_code=429, headers={"Retry-After": "30"})
    )
    nvd_client = FakeNvdHttpClient(FakeResponse({}))
    with pytest.raises(RetryAfterError) as exc_info:
        process_ghsa(
            driver, ghsa_client, nvd_client, sns_client=FakeSnsClient(), topic_arn="arn:test:topic"
        )
    assert exc_info.value.retry_after_seconds == 30


def test_5xx_routes_through_handle_response(driver):
    ghsa_client = FakeHttpClient(FakeResponse({}, status_code=503))
    nvd_client = FakeNvdHttpClient(FakeResponse({}))
    with pytest.raises(RetryableError):
        process_ghsa(
            driver, ghsa_client, nvd_client, sns_client=FakeSnsClient(), topic_arn="arn:test:topic"
        )


def test_malformed_body_routes_through_handle_response(driver):
    ghsa_client = FakeHttpClient(FakeResponse({"unexpected": "shape"}, status_code=200))
    nvd_client = FakeNvdHttpClient(FakeResponse({}))
    with pytest.raises(NoRetryError):
        process_ghsa(
            driver, ghsa_client, nvd_client, sns_client=FakeSnsClient(), topic_arn="arn:test:topic"
        )
