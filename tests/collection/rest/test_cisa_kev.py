"""Integration tests for the CISA KEV normalizer (L1 Task 9).

Runs against a real local Neo4j (docker compose up -d neo4j).

- FR-DC-22: an unseen `cveID` gets a lazy CVE stub MERGEd and on-demand NVD enrichment
  triggered; an already-present CVE is left for NVD's own delta cadence.
- FR-DC-01: `exploited_in_wild = true` + the KEV fields set as plain CVE properties, not
  an edge.
- FR-DC-19/20/21 (via Task 7): 401/429/5xx/malformed all route through `handle_response`.
"""

import json
from pathlib import Path

import pytest

from src.collection.rest.cisa_kev import CisaKevNormalizer, process_cisa_kev
from src.collection.rest.http_errors import NoRetryError, RetryableError, RetryAfterError
from src.common import config
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

    def get(self, url, params=None):
        self.calls.append({"url": url, "params": params or {}})
        return self._response


@pytest.fixture(autouse=True)
def _clear_config_cache(monkeypatch):
    config.get_config.cache_clear()
    monkeypatch.delenv("CROSSROADS_ENV", raising=False)
    yield
    config.get_config.cache_clear()


@pytest.fixture
def driver():
    d = get_driver()
    d.verify_connectivity()
    bootstrap_schema(d)
    with d.session() as s:
        s.run(
            "MATCH (n) WHERE n.test_fixture = true "
            "OR (n:CVE AND n.cve_id IN ['CVE-2026-1001', 'CVE-2026-2002']) "
            "DETACH DELETE n"
        ).consume()
        # nvd_single_cve.json's CWE-502 must already exist for enrich_cve's
        # CATEGORIZED_AS re-sync (Task 8) to find it as a MATCH endpoint.
        s.run("MERGE (w:CWE {cwe_id:'CWE-502'})").consume()
    yield d
    with d.session() as s:
        s.run(
            "MATCH (n) WHERE n.test_fixture = true "
            "OR (n:CVE AND n.cve_id IN ['CVE-2026-1001', 'CVE-2026-2002']) "
            "DETACH DELETE n"
        ).consume()
    close_driver()


def _cve_props(driver, cve_id: str) -> dict | None:
    with driver.session() as s:
        rec = s.run("MATCH (c:CVE {cve_id:$id}) RETURN c", id=cve_id).single()
    return dict(rec["c"]) if rec else None


# --- Unit: normalizer parses the fixture shape ----------------------------------


def test_normalizer_parses_fixture_shape():
    parsed = CisaKevNormalizer().parse(_load("cisa_kev_catalog.json"))
    by_id = {p.cve_id: p for p in parsed}
    assert set(by_id) == {"CVE-2026-1001", "CVE-2026-2002"}
    one = by_id["CVE-2026-1001"]
    assert one.properties["exploited_in_wild"] is True
    assert one.properties["kev_vendor_project"] == "Acme"
    assert one.properties["kev_known_ransomware_campaign_use"] == "Known"


def test_normalize_returns_node_upserts():
    upserts = CisaKevNormalizer().normalize(_load("cisa_kev_catalog.json"))
    assert {u.label for u in upserts} == {"CVE"}
    assert {u.natural_key["cve_id"] for u in upserts} == {"CVE-2026-1001", "CVE-2026-2002"}


# --- FR-DC-22: lazy stub + enrichment trigger; FR-DC-01: property not edge ------


def test_unseen_cve_gets_stub_and_enriched(driver):
    """CVE-2026-2002 is not pre-created; process_cisa_kev must MERGE the stub, set
    exploited_in_wild=true, and trigger NVD enrichment (nvd_single_cve.json) so its
    NVD-derived fields land on the same node."""
    with driver.session() as s:
        # Pre-create CVE-2026-1001 only, so it takes the "existing" path.
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-1001'}) SET c.test_fixture = true"
        ).consume()

    kev_client = FakeHttpClient(FakeResponse(_load("cisa_kev_catalog.json")))
    nvd_client = FakeHttpClient(FakeResponse(_load("nvd_single_cve.json")))

    created_count = process_cisa_kev(driver, kev_client, nvd_client)

    assert created_count == 1  # only CVE-2026-2002 was unseen

    unseen = _cve_props(driver, "CVE-2026-2002")
    assert unseen["exploited_in_wild"] is True  # FR-DC-01: plain property, not an edge
    assert unseen["kev_vendor_project"] == "Contoso"
    # NVD enrichment landed on the SAME node (FR-DC-22).
    assert unseen["cvss_score"] == 9.8
    assert "deserialization" in unseen["description"]

    existing = _cve_props(driver, "CVE-2026-1001")
    assert existing["exploited_in_wild"] is True
    assert existing["kev_vendor_project"] == "Acme"
    # The already-present CVE was NOT sent to NVD (only the new stub triggers enrichment).
    assert nvd_client.calls == [{"url": nvd_client.calls[0]["url"],
                                  "params": {"cveId": "CVE-2026-2002"}}]


def test_kev_url_has_no_auth_header_dependency(driver):
    """CISA KEV needs no credential (spec §6) -- process_cisa_kev never touches
    load_credential; this just proves the call succeeds with a bare FakeHttpClient."""
    kev_client = FakeHttpClient(FakeResponse(_load("cisa_kev_catalog.json")))
    nvd_client = FakeHttpClient(FakeResponse(_load("nvd_single_cve.json")))
    process_cisa_kev(driver, kev_client, nvd_client)
    assert kev_client.calls[0]["params"] == {}


# --- FR-DC-19/20/21 (via Task 7): handle_response routing -----------------------


def test_401_routes_through_handle_response(driver):
    kev_client = FakeHttpClient(FakeResponse({}, status_code=401))
    nvd_client = FakeHttpClient(FakeResponse({}))
    with pytest.raises(NoRetryError):
        process_cisa_kev(driver, kev_client, nvd_client)


def test_429_routes_through_handle_response(driver):
    kev_client = FakeHttpClient(
        FakeResponse({}, status_code=429, headers={"Retry-After": "30"})
    )
    nvd_client = FakeHttpClient(FakeResponse({}))
    with pytest.raises(RetryAfterError) as exc_info:
        process_cisa_kev(driver, kev_client, nvd_client)
    assert exc_info.value.retry_after_seconds == 30


def test_5xx_routes_through_handle_response(driver):
    kev_client = FakeHttpClient(FakeResponse({}, status_code=503))
    nvd_client = FakeHttpClient(FakeResponse({}))
    with pytest.raises(RetryableError):
        process_cisa_kev(driver, kev_client, nvd_client)


def test_malformed_body_routes_through_handle_response(driver):
    """A 200 body missing `vulnerabilities` fails schema validation -> NoRetryError,
    never a KeyError/crash from indexing a shape that changed."""
    kev_client = FakeHttpClient(FakeResponse({"unexpected": "shape"}, status_code=200))
    nvd_client = FakeHttpClient(FakeResponse({}))
    with pytest.raises(NoRetryError):
        process_cisa_kev(driver, kev_client, nvd_client)
