"""Integration tests for the CISA KEV normalizer (L1 Task 9).

Runs against a real local Neo4j (docker compose up -d neo4j).

- FR-DC-22: an unseen `cveID` gets a lazy CVE stub MERGEd and on-demand NVD enrichment
  triggered; an already-present CVE is left for NVD's own delta cadence.
- FR-DC-01: `exploited_in_wild = true` + the KEV fields set as plain CVE properties, not
  an edge.
- FR-DC-19/20/21 (via Task 7): 401/429/5xx/malformed all route through `handle_response`.
"""

import json
import threading
from pathlib import Path
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

from src.collection.rest.cisa_kev import (
    CisaKevNormalizer,
    ParsedKevEntry,
    _apply_kev_entry_tx,
    process_cisa_kev,
)
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


@pytest.fixture
def aws(monkeypatch):
    """Moto-mocked SNS topic for `publish_node_write` (Task 1.2). `enrich_cve` (Task 8)
    fires its own `publish_node_write` (cvss_score) on the shared on-demand enrichment
    path this module's `process_cisa_kev` also calls into (`src.collection.rest.nvd`),
    so any test exercising that path needs a real (moto) topic ARN configured -- no
    default is provided deliberately (CLAUDE.md's `00-infra` Critical: a silently
    defaulted/missing topic ARN must fail loud, not be papered over). Mirrors
    `tests/collection/rest/test_otx.py`'s `aws` fixture."""
    with mock_aws():
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
        sns = boto3.client("sns", region_name="us-east-1")
        topic_arn = sns.create_topic(Name="graph-writes")["TopicArn"]
        monkeypatch.setenv("CROSSROADS_GRAPH_WRITES_TOPIC_ARN", topic_arn)
        config.get_config.cache_clear()
        yield
        config.get_config.cache_clear()


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


def test_unseen_cve_gets_stub_and_enriched(driver, aws):
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

    # Both CVEs flip exploited_in_wild here (neither was pre-set), and the unseen one's
    # enrich_cve call fires its own cvss_score node_write -- real (moto) publishes via
    # the `aws` fixture rather than muting the KEV flip announcement this test isn't about.
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


def test_kev_url_has_no_auth_header_dependency(driver, aws):
    """CISA KEV needs no credential (spec §6) -- process_cisa_kev never touches
    load_credential; this just proves the call succeeds with a bare FakeHttpClient."""
    kev_client = FakeHttpClient(FakeResponse(_load("cisa_kev_catalog.json")))
    nvd_client = FakeHttpClient(FakeResponse(_load("nvd_single_cve.json")))
    process_cisa_kev(driver, kev_client, nvd_client)
    assert kev_client.calls[0]["params"] == {}


# --- FR-DC-19/20/21 (via Task 7): handle_response routing -----------------------


# --- Task 1.2: node_write publish on a real exploited_in_wild flip -------------


def test_kev_flip_publishes_a_node_write(driver, aws):
    """A CVE that is not yet KEV-listed must announce itself when this run flips
    exploited_in_wild true -> the single most urgent severity input, and the daily
    sweep alone would leave it up to 24h stale."""
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-1001'}) SET c.test_fixture = true"
        ).consume()

    kev_client = FakeHttpClient(FakeResponse(_load("cisa_kev_catalog.json")))
    nvd_client = FakeHttpClient(FakeResponse(_load("nvd_single_cve.json")))

    # CVE-2026-2002's enrich_cve leg publishes for real onto the moto topic (`aws`); we
    # only need to intercept THIS module's own KEV-flip publish call to assert on it.
    with patch("src.collection.rest.cisa_kev.publish_node_write") as pub:
        process_cisa_kev(driver, kev_client, nvd_client)

    calls_by_cve = {c.kwargs["key"]["cve_id"]: c for c in pub.call_args_list}
    assert "CVE-2026-1001" in calls_by_cve
    kwargs = calls_by_cve["CVE-2026-1001"].kwargs
    assert kwargs["label"] == "CVE"
    assert kwargs["changed_fields"] == ["exploited_in_wild"]
    assert kwargs["origin"] == "cisa-kev"


def test_kev_republish_of_an_already_listed_cve_does_not_announce(driver, aws):
    """Idempotency: KEV re-publishes its whole catalog daily. Announcing all ~1200
    entries every day would swamp the event path with no-ops."""
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-1001'}) "
            "SET c.test_fixture = true, c.exploited_in_wild = true"
        ).consume()

    kev_client = FakeHttpClient(FakeResponse(_load("cisa_kev_catalog.json")))
    nvd_client = FakeHttpClient(FakeResponse(_load("nvd_single_cve.json")))

    with patch("src.collection.rest.cisa_kev.publish_node_write") as pub:
        process_cisa_kev(driver, kev_client, nvd_client)

    calls_for_1001 = [
        c for c in pub.call_args_list if c.kwargs["key"]["cve_id"] == "CVE-2026-1001"
    ]
    assert calls_for_1001 == []


def test_mid_loop_failure_does_not_lose_earlier_announcements(driver, aws):
    """Fix round 1, I2 regression: publishing must happen per-entry, immediately after
    that entry's own transaction commits -- NOT batched to the end of the loop.

    The catalog fixture lists CVE-2026-1001 before CVE-2026-2002. We force the SECOND
    entry's `_apply_kev_entry_tx` to raise (simulating a Neo4j blip / Lambda timeout)
    and prove the FIRST entry's flip was both committed AND announced before the crash
    propagates -- i.e. the exception does not retroactively unwind the first
    announcement. With the old end-of-loop batching, the whole `flipped_cve_ids` list
    (including CVE-2026-1001) would be discarded when the loop raised, and a retry
    would never re-announce it because `exploited_in_wild` is already `true`."""
    import src.collection.rest.cisa_kev as cisa_kev_module

    original_apply = cisa_kev_module._apply_kev_entry_tx

    def _raise_on_second_entry(tx, entry):
        if entry.cve_id == "CVE-2026-2002":
            raise RuntimeError("simulated Neo4j blip")
        return original_apply(tx, entry)

    kev_client = FakeHttpClient(FakeResponse(_load("cisa_kev_catalog.json")))
    nvd_client = FakeHttpClient(FakeResponse(_load("nvd_single_cve.json")))

    with (
        patch(
            "src.collection.rest.cisa_kev._apply_kev_entry_tx",
            side_effect=_raise_on_second_entry,
        ),
        patch("src.collection.rest.cisa_kev.publish_node_write") as pub,
        pytest.raises(RuntimeError, match="simulated Neo4j blip"),
    ):
        process_cisa_kev(driver, kev_client, nvd_client)

    # The first entry's write committed for real despite the second entry's crash.
    assert _cve_props(driver, "CVE-2026-1001")["exploited_in_wild"] is True
    # ...and it was announced BEFORE the crash propagated, not discarded with it.
    announced_cves = {c.kwargs["key"]["cve_id"] for c in pub.call_args_list}
    assert announced_cves == {"CVE-2026-1001"}


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


def test_concurrent_kev_flips_announce_exactly_once(driver):
    """FR-DC-01. Ten runners race to flip `exploited_in_wild` false->true on ONE CVE.
    Exactly one may report `flipped` -- that caller owns the announce. Without a working
    lock all ten read the same pre-lock `false` and all ten announce."""
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-1001'}) "
            "SET c.test_fixture = true, c.exploited_in_wild = false"
        ).consume()

    entry = ParsedKevEntry(cve_id="CVE-2026-1001", properties={"exploited_in_wild": True})
    flips, errors = [], []

    def flip():
        try:
            with driver.session() as s:
                _, flipped = s.execute_write(_apply_kev_entry_tx, entry)
            flips.append(flipped)
        except Exception as exc:      # noqa: BLE001 - surfaced via the assert below
            errors.append(exc)

    threads = [threading.Thread(target=flip) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(flips) == 10
    assert sum(flips) == 1, f"expected exactly one announce, got {sum(flips)}"
