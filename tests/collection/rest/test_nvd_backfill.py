"""Integration tests for the one-shot NVD backfill (bare KEV/GHSA stubs -> full CVEs).

Runs against a real local Neo4j (docker compose up -d neo4j).

The backfill exists because 1667 of 1735 CVE nodes in the live graph had never been
touched by NVD: CISA KEV and GHSA MERGE bare `cve_id` stubs (FR-DC-22), and the delta
poll only ever revisits CVEs NVD itself has recently modified (FR-DC-17/23), so a stub
for an old CVE is never picked up by anything. These tests cover the three pieces that
are genuinely new -- the resumable work list, the rate limiter, and the retry/abort
policy -- not the enrichment itself, which `test_nvd.py` already covers.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.collection.rest.http_errors import NoRetryError
from src.collection.rest.nvd_backfill import (
    RateLimiter,
    backfill,
    find_unenriched_cve_ids,
)
from src.common.neo4j_driver import close_driver, get_driver
from src.common.schema_bootstrap import bootstrap_schema

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


class FakeResponse:
    def __init__(self, body: dict, status_code: int = 200, headers: dict | None = None):
        self._body = body
        self.status_code = status_code
        self.headers = headers or {}

    def json(self) -> dict:
        return self._body


class ScriptedHttpClient:
    """Returns a queued response per GET, recording the params it was called with.

    A single (non-list) `responses` value is returned for every call.
    """

    def __init__(self, responses):
        self._responses = responses
        self.calls: list[dict] = []

    def get(self, url: str, params: dict | None = None):
        self.calls.append(params or {})
        if isinstance(self._responses, list):
            return self._responses.pop(0)
        return self._responses


@pytest.fixture(autouse=True)
def _no_publish():
    """`enrich_cve` publishes a node_write on a CVSS change; no SNS in these tests."""
    with patch("src.collection.rest.nvd.publish_node_write"):
        yield


@pytest.fixture
def driver():
    d = get_driver()
    bootstrap_schema(d)
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
        s.run("MERGE (c:CWE {cwe_id:'CWE-502'}) SET c.test_fixture = true").consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


def _stub(driver, *cve_ids: str, **props) -> None:
    with driver.session() as s:
        for cve_id in cve_ids:
            s.run(
                "MERGE (c:CVE {cve_id:$id}) SET c.test_fixture = true, c += $props",
                id=cve_id,
                props=props,
            ).consume()


def _prop(driver, cve_id: str, name: str):
    with driver.session() as s:
        row = s.run(
            f"MATCH (c:CVE {{cve_id:$id}}) RETURN c.`{name}` AS v", id=cve_id
        ).single()
    return None if row is None else row["v"]


# --- work list -------------------------------------------------------------------


def test_work_list_finds_only_never_enriched_stubs(driver):
    """`last_modified_date` is the enrichment watermark: its absence means NVD has never
    written this node. A fully caught-up CVE (with MATCHES edges) must not be
    re-fetched -- that is what makes a re-run after a crash resume rather than restart."""
    _stub(driver, "CVE-2026-7001")
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-7002'}) "
            "SET c.last_modified_date = '2026-01-01T00:00:00.000' "
            "MERGE (m:CPEMatch {match_criteria_id:'MC-Y'}) "
            "MERGE (c)-[:MATCHES]->(m)"
        ).consume()

    ids = find_unenriched_cve_ids(driver)

    assert "CVE-2026-7001" in ids
    assert "CVE-2026-7002" not in ids

    with driver.session() as s:
        s.run("MATCH (m:CPEMatch {match_criteria_id:'MC-Y'}) DETACH DELETE m").consume()


def test_work_list_excludes_cves_nvd_does_not_have(driver):
    """A CVE NVD has no record of never gets a `last_modified_date`, so without this
    exclusion every future run would retry it forever."""
    _stub(driver, "CVE-2026-7003", nvd_not_found_at="2026-08-16T00:00:00+00:00")

    assert "CVE-2026-7003" not in find_unenriched_cve_ids(driver)


def test_find_unenriched_cve_ids_includes_already_enriched_cves_missing_cpe_matches(driver):
    with driver.session() as s:
        # Old-shape: already has last_modified_date (enriched before this feature existed)
        # but no CPEMatch nodes.
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-7001'}) "
            "SET c.last_modified_date = '2026-01-01T00:00:00Z'"
        ).consume()
        # Fully caught up: has both.
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-7002'}) "
            "SET c.last_modified_date = '2026-01-01T00:00:00Z' "
            "MERGE (m:CPEMatch {match_criteria_id:'MC-X'}) "
            "MERGE (c)-[:MATCHES]->(m)"
        ).consume()
    ids = find_unenriched_cve_ids(driver)
    assert "CVE-2026-7001" in ids
    assert "CVE-2026-7002" not in ids
    with driver.session() as s:
        s.run(
            "MATCH (c:CVE) WHERE c.cve_id IN ['CVE-2026-7001','CVE-2026-7002'] DETACH DELETE c"
        ).consume()
        s.run("MATCH (m:CPEMatch {match_criteria_id:'MC-X'}) DETACH DELETE m").consume()


def test_work_list_honours_limit(driver):
    _stub(driver, "CVE-2026-7101", "CVE-2026-7102", "CVE-2026-7103")

    assert len(find_unenriched_cve_ids(driver, limit=2)) == 2


# --- rate limiter ----------------------------------------------------------------


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def test_rate_limiter_allows_a_full_window_without_sleeping():
    clock = FakeClock()
    limiter = RateLimiter(3, 30.0, sleep=clock.sleep, monotonic=clock.monotonic)

    for _ in range(3):
        limiter.acquire()

    assert clock.slept == []


def test_rate_limiter_sleeps_until_the_oldest_request_leaves_the_window():
    """NVD's limit is a rolling window, so the (n+1)th request must wait out the
    remainder of the FIRST request's window, not a fixed per-request delay."""
    clock = FakeClock()
    limiter = RateLimiter(2, 30.0, sleep=clock.sleep, monotonic=clock.monotonic)

    limiter.acquire()
    clock.now = 10.0
    limiter.acquire()
    limiter.acquire()

    assert clock.slept == [20.0]


# --- backfill loop ---------------------------------------------------------------


def test_backfill_enriches_a_bare_stub(driver):
    _stub(driver, "CVE-2026-2002")
    client = ScriptedHttpClient(FakeResponse(_load("nvd_single_cve.json")))

    result = backfill(driver, client, rate_limiter=None)

    assert result.enriched >= 1
    assert _prop(driver, "CVE-2026-2002", "cvss_score") is not None
    assert _prop(driver, "CVE-2026-2002", "last_modified_date") is not None
    assert client.calls[0]["cveId"] == "CVE-2026-2002"


def test_backfill_marks_a_cve_nvd_does_not_have(driver):
    """NVD answers an unknown id with 200 and an empty `vulnerabilities` list rather
    than a 404, so a miss is invisible unless the loop checks for it explicitly."""
    _stub(driver, "CVE-2026-7004")
    client = ScriptedHttpClient(FakeResponse({"vulnerabilities": [], "totalResults": 0}))

    result = backfill(driver, client, rate_limiter=None)

    assert result.not_found == 1
    assert result.enriched == 0
    assert _prop(driver, "CVE-2026-7004", "nvd_not_found_at") is not None
    assert find_unenriched_cve_ids(driver) == []


def test_backfill_retries_after_a_rate_limit_then_succeeds(driver):
    """`handle_response` classifies only -- it never sleeps or retries, by design. A
    429 mid-run must not abandon the remaining CVEs."""
    _stub(driver, "CVE-2026-2002")
    client = ScriptedHttpClient(
        [
            FakeResponse({}, status_code=429, headers={"Retry-After": "7"}),
            FakeResponse(_load("nvd_single_cve.json")),
        ]
    )
    slept: list[float] = []

    result = backfill(driver, client, rate_limiter=None, sleep=slept.append)

    assert result.enriched == 1
    assert slept == [7.0]
    assert _prop(driver, "CVE-2026-2002", "cvss_score") is not None


def test_backfill_aborts_on_auth_failure_without_marking_anything_not_found(driver):
    """A bad API key is a 403, which `handle_response` raises as NoRetryError -- the
    same exception class a malformed request gets. Swallowing it per-CVE would stamp
    `nvd_not_found_at` on every CVE in the work list and permanently exclude them."""
    _stub(driver, "CVE-2026-7005")
    client = ScriptedHttpClient(FakeResponse({}, status_code=403))

    with pytest.raises(NoRetryError):
        backfill(driver, client, rate_limiter=None)

    assert _prop(driver, "CVE-2026-7005", "nvd_not_found_at") is None
