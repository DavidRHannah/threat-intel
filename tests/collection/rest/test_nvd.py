"""Integration tests for the NVD delta poll + lazy CVE enrichment normalizer (L1 Task 8).

Runs against a real local Neo4j (docker compose up -d neo4j). Covers the four base
acceptance criteria and the CATEGORIZED_AS resurrection-race regression:

- FR-DC-17: the delta request carries `lastModStartDate == last_success_at`.
- FR-DC-22: an unenriched CVE stub gets its fields populated by `enrich_cve`.
- FR-DC-23: the delta poll updates existing CVEs only and never creates a node for an
  unreferenced CVE in the delta.
- FR-DC-25: the request URL pins the configured NVD API version.
- Resurrection race: a stale (older `lastModified`) payload must NOT re-create a
  CATEGORIZED_AS edge that a newer payload already correctly removed.
"""

import copy
import json
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from src.collection.rest.nvd import (
    NvdNormalizer,
    ParsedCve,
    _apply_cve_tx,
    _cpe_matches,
    enrich_cve,
    poll_nvd_delta,
)
from src.common import config
from src.common.neo4j_driver import close_driver, get_driver
from src.common.schema_bootstrap import bootstrap_schema

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


class FakeResponse:
    """Minimal httpx/requests-shaped response for `handle_response`."""

    def __init__(self, body: dict, status_code: int = 200):
        self._body = body
        self.status_code = status_code
        self.headers: dict = {}

    def json(self) -> dict:
        return self._body


class FakeHttpClient:
    """Records the last GET call and returns a queued/response body."""

    def __init__(self, body: dict, status_code: int = 200):
        self._response = FakeResponse(body, status_code)
        self.calls: list[dict] = []

    def get(self, url, params=None):
        self.calls.append({"url": url, "params": params or {}})
        return self._response


def _cve_envelope(cve_id: str, last_modified: str, cwe_ids: list[str], base_score: float) -> dict:
    """Build a single-CVE NVD v2.0 envelope for the race test's crafted snapshots."""
    return {
        "version": "2.0",
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2026-01-01T00:00:00.000",
                    "lastModified": last_modified,
                    "descriptions": [{"lang": "en", "value": f"desc for {cve_id}"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseScore": base_score,
                                }
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "description": [{"lang": "en", "value": w} for w in cwe_ids],
                        }
                    ],
                    "configurations": [],
                }
            }
        ],
    }


@pytest.fixture(autouse=True)
def _clear_config_cache(monkeypatch):
    config.get_config.cache_clear()
    monkeypatch.delenv("CROSSROADS_ENV", raising=False)
    monkeypatch.delenv("CROSSROADS_NVD_API_VERSION", raising=False)
    yield
    config.get_config.cache_clear()




@pytest.fixture
def driver():
    d = get_driver()
    d.verify_connectivity()
    bootstrap_schema(d)
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
        # CWE nodes the fixtures/race scenarios categorize against.
        s.run(
            "MERGE (a:CWE {cwe_id:'CWE-79'}) SET a.test_fixture = true "
            "MERGE (b:CWE {cwe_id:'CWE-89'}) SET b.test_fixture = true "
            "MERGE (c:CWE {cwe_id:'CWE-502'}) SET c.test_fixture = true"
        ).consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


def _cve_props(driver, cve_id: str) -> dict | None:
    with driver.session() as s:
        rec = s.run("MATCH (c:CVE {cve_id:$id}) RETURN c", id=cve_id).single()
    return dict(rec["c"]) if rec else None


def _cwe_ids(driver, cve_id: str) -> set[str]:
    with driver.session() as s:
        rows = s.run(
            "MATCH (:CVE {cve_id:$id})-[:CATEGORIZED_AS]->(w:CWE) RETURN w.cwe_id AS id",
            id=cve_id,
        )
        return {r["id"] for r in rows}


# --- FR-DC-23: delta updates existing CVEs only, never creates -----------------


def test_delta_poll_updates_existing_and_never_creates(driver):
    # Pre-create ONLY CVE-2026-1001; the fixture also carries 1002 and 1003.
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-1001'}) "
            "SET c.test_fixture = true, c.cvss_score = 1.0"
        ).consume()

    client = FakeHttpClient(_load("nvd_delta_response.json"))
    # cvss_score changes 1.0 -> 7.5 here; not what this test is about, so mute the publish.
    with patch("src.collection.rest.nvd.publish_node_write"):
        count, _window_end = poll_nvd_delta(driver, client, "2026-07-10T00:00:00.000")

    updated = _cve_props(driver, "CVE-2026-1001")
    assert updated is not None
    assert updated["cvss_score"] == 7.5  # FR-DC-23: existing CVE's fields updated
    assert "SQL injection" in updated["description"]
    # FR-DC-23: unreferenced delta CVEs are NOT created.
    assert _cve_props(driver, "CVE-2026-1002") is None
    assert _cve_props(driver, "CVE-2026-1003") is None
    assert count == 1  # only the one existing CVE was updated


def test_delta_poll_resyncs_cwe_for_existing_cve(driver):
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-1001'}) SET c.test_fixture = true"
        ).consume()

    with patch("src.collection.rest.nvd.publish_node_write"):
        poll_nvd_delta(driver, FakeHttpClient(_load("nvd_delta_response.json")),
                       "2026-07-10T00:00:00.000")

    assert _cwe_ids(driver, "CVE-2026-1001") == {"CWE-89"}


# --- FR-DC-22: lazy CVE creation + on-demand enrichment ------------------------


def test_enrich_populates_bare_stub(driver):
    # Simulate a GHSA/CISA-KEV caller MERGEing a bare stub the graph hasn't seen.
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-2002'}) SET c.test_fixture = true"
        ).consume()
    before = _cve_props(driver, "CVE-2026-2002")
    assert "cvss_score" not in before  # bare stub

    client = FakeHttpClient(_load("nvd_single_cve.json"))
    with patch("src.collection.rest.nvd.publish_node_write"):
        enrich_cve(driver, client, "CVE-2026-2002")

    after = _cve_props(driver, "CVE-2026-2002")
    assert after["cvss_score"] == 9.8  # FR-DC-22
    assert "deserialization" in after["description"]
    assert after["cvss_vector"].startswith("CVSS:3.1")
    assert _cwe_ids(driver, "CVE-2026-2002") == {"CWE-502"}
    # enrich_cve queries NVD by the specific cve_id.
    assert client.calls[0]["params"].get("cveId") == "CVE-2026-2002"


def test_enrich_cve_writes_cpe_match_nodes(driver):
    # nvd_delta_response.json's CVE-2026-1001 carries one cpeMatch entry.
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-1001'}) SET c.test_fixture = true"
        ).consume()

    client = FakeHttpClient(_load("nvd_delta_response.json"))
    with patch("src.collection.rest.nvd.publish_node_write"):
        enrich_cve(driver, client, "CVE-2026-1001")

    with driver.session() as s:
        s.run("MATCH (m:CPEMatch) SET m.test_fixture = true").consume()
        row = s.run(
            "MATCH (:CVE {cve_id:'CVE-2026-1001'})-[:MATCHES]->(m:CPEMatch) RETURN count(m) AS n"
        ).single()
        assert row["n"] >= 1


# --- Task 1.2: node_write publish on a real cvss_score change ------------------


def test_cvss_change_publishes_a_node_write(driver):
    """A CVE whose CVSS score actually changes must announce itself so L4 can recompute
    severity without waiting for the next full sweep."""
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-1001'}) "
            "SET c.test_fixture = true, c.cvss_score = 1.0"
        ).consume()

    client = FakeHttpClient(_load("nvd_delta_response.json"))
    with patch("src.collection.rest.nvd.publish_node_write") as pub:
        poll_nvd_delta(driver, client, "2026-07-10T00:00:00.000")

    # Filter to CVE-labelled announcements: the same publisher now also carries the
    # post-commit CPEMatch announcements (final-review finding #1), keyed differently.
    calls_by_cve = {
        c.kwargs["key"]["cve_id"]: c
        for c in pub.call_args_list
        if c.kwargs["label"] == "CVE"
    }
    assert "CVE-2026-1001" in calls_by_cve
    kwargs = calls_by_cve["CVE-2026-1001"].kwargs
    assert kwargs["label"] == "CVE"
    assert kwargs["changed_fields"] == ["cvss_score"]
    assert kwargs.get("origin") is None


def test_reapplying_an_identical_cvss_score_does_not_announce(driver):
    """Idempotency: NVD re-enriches the same CVEs repeatedly. Announcing on every
    re-enrichment with an unchanged score would flood the event path with no-ops."""
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-1001'}) "
            "SET c.test_fixture = true, c.cvss_score = 7.5"
        ).consume()

    client = FakeHttpClient(_load("nvd_delta_response.json"))
    with patch("src.collection.rest.nvd.publish_node_write") as pub:
        poll_nvd_delta(driver, client, "2026-07-10T00:00:00.000")

    calls_for_1001 = [
        c
        for c in pub.call_args_list
        if c.kwargs["label"] == "CVE" and c.kwargs["key"]["cve_id"] == "CVE-2026-1001"
    ]
    assert calls_for_1001 == []


def test_mid_loop_failure_does_not_lose_earlier_announcements(driver):
    """Fix round 1, I2 regression: publishing must happen per-record, immediately
    after that record's own transaction commits -- NOT batched to the end of the loop.

    `nvd_delta_response.json` lists CVE-2026-1001 before CVE-2026-1002. Both are
    pre-created with scores that will change. We force `_apply_cve_tx` to raise on the
    SECOND record (simulating a Neo4j blip / Lambda timeout) and prove the FIRST
    record's cvss_score change was both committed AND announced before the crash
    propagates. With the old end-of-loop batching, the whole `cvss_changed_ids` list
    (including CVE-2026-1001) would be discarded when the loop raised, and a retry
    would never re-announce it because cvss_score is already updated to 7.5."""
    import src.collection.rest.nvd as nvd_module

    original_apply = nvd_module._apply_cve_tx

    def _raise_on_second_record(tx, parsed, *, allow_create):
        if parsed.cve_id == "CVE-2026-1002":
            raise RuntimeError("simulated Neo4j blip")
        return original_apply(tx, parsed, allow_create=allow_create)

    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-1001'}) "
            "SET c.test_fixture = true, c.cvss_score = 1.0"
        ).consume()
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-1002'}) "
            "SET c.test_fixture = true, c.cvss_score = 2.0"
        ).consume()

    client = FakeHttpClient(_load("nvd_delta_response.json"))

    with (
        patch(
            "src.collection.rest.nvd._apply_cve_tx", side_effect=_raise_on_second_record
        ),
        patch("src.collection.rest.nvd.publish_node_write") as pub,
        pytest.raises(RuntimeError, match="simulated Neo4j blip"),
    ):
        poll_nvd_delta(driver, client, "2026-07-10T00:00:00.000")

    # The first record's write committed for real despite the second record's crash.
    assert _cve_props(driver, "CVE-2026-1001")["cvss_score"] == 7.5
    # ...and it was announced BEFORE the crash propagated, not discarded with it.
    announced_cves = {
        c.kwargs["key"]["cve_id"]
        for c in pub.call_args_list
        if c.kwargs["label"] == "CVE"
    }
    assert announced_cves == {"CVE-2026-1001"}


# --- FR-DC-17: delta request carries lastModStartDate == last_success_at -------


def test_delta_request_carries_last_success_at(driver):
    client = FakeHttpClient(_load("nvd_delta_response.json"))
    last_success_at = "2026-07-10T00:00:00.000"
    poll_nvd_delta(driver, client, last_success_at)

    assert client.calls, "http client was never called"
    assert client.calls[0]["params"]["lastModStartDate"] == last_success_at  # FR-DC-17


# --- FR-DC-25: request URL pins the configured API version ---------------------


def test_request_url_pins_configured_api_version(driver, monkeypatch):
    monkeypatch.setenv("CROSSROADS_NVD_API_VERSION", "2.0")
    config.get_config.cache_clear()
    client = FakeHttpClient(_load("nvd_delta_response.json"))
    poll_nvd_delta(driver, client, "2026-07-10T00:00:00.000")

    assert "2.0" in client.calls[0]["url"]  # FR-DC-25


# --- Regression: CATEGORIZED_AS resurrection race ------------------------------


def test_stale_payload_does_not_resurrect_dropped_cwe(driver):
    """A stale (older lastModified) enrichment payload processed AFTER a newer one must
    not re-create a CATEGORIZED_AS edge the newer payload already correctly removed.

    Timeline:
      T1  CVE holds {CWE-79, CWE-89}, last_modified_date = T1 (initial state).
      T2  newer payload (>T1), CWE list {CWE-79} only  -> correctly deletes CWE-89.
      T0  stale payload (<T1), CWE list {CWE-79, CWE-89} -> must be a NO-OP for CWEs.

    Without the freshness guard, processing the T0 payload would resurrect CWE-89.
    """
    t0 = "2026-07-01T00:00:00.000"
    t1 = "2026-07-05T00:00:00.000"
    t2 = "2026-07-10T00:00:00.000"

    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-9999'}) "
            "SET c.test_fixture = true, c.last_modified_date = $t1 "
            "WITH c "
            "MATCH (a:CWE {cwe_id:'CWE-79'}), (b:CWE {cwe_id:'CWE-89'}) "
            "MERGE (c)-[:CATEGORIZED_AS]->(a) "
            "MERGE (c)-[:CATEGORIZED_AS]->(b)",
            t1=t1,
        ).consume()
    assert _cwe_ids(driver, "CVE-2026-9999") == {"CWE-79", "CWE-89"}

    # Newer payload commits first: drops CWE-89.
    newer = _cve_envelope("CVE-2026-9999", t2, ["CWE-79"], 5.0)
    with patch("src.collection.rest.nvd.publish_node_write"):
        enrich_cve(driver, FakeHttpClient(newer), "CVE-2026-9999")
    assert _cwe_ids(driver, "CVE-2026-9999") == {"CWE-79"}

    # Stale payload commits second: still lists CWE-89, but is older -> must skip resync.
    stale = _cve_envelope("CVE-2026-9999", t0, ["CWE-79", "CWE-89"], 5.0)
    with patch("src.collection.rest.nvd.publish_node_write"):
        enrich_cve(driver, FakeHttpClient(stale), "CVE-2026-9999")

    assert _cwe_ids(driver, "CVE-2026-9999") == {"CWE-79"}  # CWE-89 NOT resurrected


def test_enrich_creates_missing_cwe_stub_node(driver):
    """Regression (Critical): nothing in src/ MERGEs a CWE node, yet resync_categorized_as
    goes through merge_relationship, which MATCHes both endpoints and raises
    EndpointNotFoundError if the CWE is absent. Every other test here pre-seeds the CWE via
    the `driver` fixture (CWE-79/89/502), masking the real production shape: an existing CVE
    carrying a CWE for which no node exists. `_apply_cve_tx` must MERGE the CWE stub before
    the re-sync. Uses CWE-611 (NOT pre-seeded) to reproduce the gap.
    """
    # Real production shape: the CVE exists, but no CWE-611 node has ever been created.
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-6011'}) SET c.test_fixture = true"
        ).consume()
        assert s.run("MATCH (w:CWE {cwe_id:'CWE-611'}) RETURN w").single() is None

    try:
        payload = _cve_envelope("CVE-2026-6011", "2026-07-20T00:00:00.000", ["CWE-611"], 8.1)
        with patch("src.collection.rest.nvd.publish_node_write"):
            enrich_cve(driver, FakeHttpClient(payload), "CVE-2026-6011")

        # The stub node now exists and the CATEGORIZED_AS edge was created.
        with driver.session() as s:
            assert (
                s.run("MATCH (w:CWE {cwe_id:'CWE-611'}) RETURN w").single() is not None
            )
        assert _cwe_ids(driver, "CVE-2026-6011") == {"CWE-611"}
    finally:
        with driver.session() as s:
            s.run("MATCH (w:CWE {cwe_id:'CWE-611'}) DETACH DELETE w").consume()


def test_normalizer_parses_fixture_shape():
    """Unit-level: the normalizer maps NVD v2.0 JSON to parsed CVE records."""
    parsed = NvdNormalizer().parse(_load("nvd_delta_response.json"))
    by_id = {p.cve_id: p for p in parsed}
    assert set(by_id) == {"CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"}
    one = by_id["CVE-2026-1001"]
    assert one.last_modified == "2026-07-19T09:30:00.000"
    assert one.cwe_ids == ["CWE-89"]
    assert one.properties["cvss_score"] == 7.5
    assert one.properties["cvss_vector"].startswith("CVSS:3.1")
    assert "SQL injection" in one.properties["description"]
    assert one.cpe_matches[0]["vendor"] == "acme"
    assert one.cpe_matches[0]["product"] == "reporting"
    assert one.cpe_matches[0]["version"] == "1.2.0"
    # A CVE with empty metrics/weaknesses parses without those keys, no crash.
    assert by_id["CVE-2026-1003"].cwe_ids == []


def test_deep_copy_isolation_sanity():
    """Guard against fixture mutation leaking across tests via shared dict refs."""
    a = _load("nvd_delta_response.json")
    b = copy.deepcopy(a)
    assert a == b


def test_concurrent_cvss_changes_announce_exactly_once(driver):
    """FR-DC-22. Ten runners write the SAME new cvss_score over a differing stored value.
    Exactly one may report `cvss_changed`. Without a working lock all ten read the stale
    5.0 and all ten announce a change that only happened once."""
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-2002'}) "
            "SET c.test_fixture = true, c.cvss_score = 5.0"
        ).consume()

    parsed = ParsedCve(
        cve_id="CVE-2026-2002",
        last_modified=None,
        properties={"cvss_score": 9.8},
        cwe_ids=[],
    )
    changes, errors = [], []

    def apply_once():
        try:
            with driver.session() as s:
                _, changed, _created = s.execute_write(_apply_cve_tx, parsed, allow_create=False)
            changes.append(changed)
        except Exception as exc:      # noqa: BLE001 - surfaced via the assert below
            errors.append(exc)

    threads = [threading.Thread(target=apply_once) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(changes) == 10
    assert sum(changes) == 1, f"expected exactly one announce, got {sum(changes)}"


def test_concurrent_allow_create_cvss_changes_announce_exactly_once(driver):
    """FR-DC-22, `allow_create=True` path. `enrich_cve`'s on-demand enrichment (triggered
    by KEV) races the NVD delta poll, GHSA, and OTX over the SAME CVE via non-FIFO SQS --
    so this branch, not just the delta (`allow_create=False`) branch, needs the identical
    post-lock re-MATCH. Ten runners write the SAME new cvss_score over a differing stored
    value; exactly one may report `cvss_changed`."""
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-3003'}) "
            "SET c.test_fixture = true, c.cvss_score = 5.0"
        ).consume()

    parsed = ParsedCve(
        cve_id="CVE-2026-3003",
        last_modified=None,
        properties={"cvss_score": 9.8},
        cwe_ids=[],
    )
    changes, errors = [], []

    def apply_once():
        try:
            with driver.session() as s:
                _, changed, _created = s.execute_write(_apply_cve_tx, parsed, allow_create=True)
            changes.append(changed)
        except Exception as exc:      # noqa: BLE001 - surfaced via the assert below
            errors.append(exc)

    threads = [threading.Thread(target=apply_once) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(changes) == 10
    assert sum(changes) == 1, f"expected exactly one announce, got {sum(changes)}"


# --- Task 1: CPE match extraction -----------------------------------------------


def test_cpe_matches_extracts_vendor_product_from_criteria():
    configurations = [{
        "nodes": [{
            "cpeMatch": [{
                "matchCriteriaId": "ABC-123",
                "criteria": "cpe:2.3:a:acme:reporting:1.2.0:*:*:*:*:*:*:*",
                "vulnerable": True,
            }]
        }]
    }]
    matches = _cpe_matches(configurations)
    assert matches == [{
        "match_criteria_id": "ABC-123",
        "criteria": "cpe:2.3:a:acme:reporting:1.2.0:*:*:*:*:*:*:*",
        "vendor": "acme",
        "product": "reporting",
        "version": "1.2.0",
        "version_start_including": None,
        "version_start_excluding": None,
        "version_end_including": None,
        "version_end_excluding": None,
        "vulnerable": True,
    }]


def test_cpe_matches_extracts_version_ranges_and_drops_wildcard_version():
    configurations = [{
        "nodes": [{
            "cpeMatch": [{
                "matchCriteriaId": "DEF-456",
                "criteria": "cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "17.3.0",
                "versionEndExcluding": "17.3.5",
                "vulnerable": True,
            }]
        }]
    }]
    matches = _cpe_matches(configurations)
    assert matches[0]["version"] is None  # "*" is a wildcard, not an exact pin
    assert matches[0]["version_start_including"] == "17.3.0"
    assert matches[0]["version_end_excluding"] == "17.3.5"


def test_cpe_matches_dedupes_on_match_criteria_id():
    configurations = [
        {"nodes": [{"cpeMatch": [{
            "matchCriteriaId": "SAME-ID",
            "criteria": "cpe:2.3:a:acme:x:1.0:*:*:*:*:*:*:*",
            "vulnerable": True,
        }]}]},
        {"nodes": [{"cpeMatch": [{
            "matchCriteriaId": "SAME-ID",
            "criteria": "cpe:2.3:a:acme:x:1.0:*:*:*:*:*:*:*",
            "vulnerable": True,
        }]}]},
    ]
    assert len(_cpe_matches(configurations)) == 1


# --- Final-review finding #1: CPEMatch announcements are post-commit and guardable -----


class TestCpeMatchPublishing:
    """`resync_matches` used to publish a `node_write` per newly-created CPEMatch from
    INSIDE `_apply_cve_tx`'s `session.execute_write` callback, which was wrong twice
    over: pre-commit (a subscriber could read a node that does not exist yet) and
    unconditional (bypassing `enrich_cve`/`backfill`'s `publish=False` guard, so a bulk
    backfill would fan ~10^5 announcements at L4 and the assets matcher).
    """

    @staticmethod
    def _stub(driver, cve_id: str) -> None:
        with driver.session() as s:
            s.run(
                "MERGE (c:CVE {cve_id:$id}) SET c.test_fixture = true", id=cve_id
            ).consume()

    @staticmethod
    def _cleanup(driver) -> None:
        with driver.session() as s:
            s.run("MATCH (m:CPEMatch) DETACH DELETE m").consume()

    def test_publishes_created_cpe_match_after_the_transaction_commits(self, driver):
        self._stub(driver, "CVE-2026-1001")
        client = FakeHttpClient(_load("nvd_delta_response.json"))

        visible_at_publish_time: list[int] = []

        def _record(**kwargs):
            if kwargs.get("label") != "CPEMatch":
                return
            # A brand new session: it can only see state the writing transaction has
            # already COMMITTED. If the publish still fired inside execute_write, this
            # read would come back 0.
            with driver.session() as s:
                visible_at_publish_time.append(
                    s.run(
                        "MATCH (m:CPEMatch {match_criteria_id:$id}) RETURN count(m) AS n",
                        id=kwargs["key"]["match_criteria_id"],
                    ).single()["n"]
                )

        try:
            with patch(
                "src.collection.rest.nvd.publish_node_write", side_effect=_record
            ) as mock_publish:
                enrich_cve(driver, client, "CVE-2026-1001")

            cpe_calls = [
                c for c in mock_publish.call_args_list if c.kwargs.get("label") == "CPEMatch"
            ]
            assert cpe_calls, "no CPEMatch node_write announced for a newly-created match"
            assert all(c.kwargs["changed_fields"] == ["created"] for c in cpe_calls)
            assert visible_at_publish_time and all(n == 1 for n in visible_at_publish_time), (
                "CPEMatch was announced before its transaction committed"
            )
        finally:
            self._cleanup(driver)

    def test_publish_false_suppresses_the_cpe_match_announcement(self, driver):
        self._stub(driver, "CVE-2026-1001")
        client = FakeHttpClient(_load("nvd_delta_response.json"))
        try:
            # Patched at the DEFINITION site so no import path can slip past it -- the
            # old bug published through structural_edges' own import of this name.
            with patch("src.common.graph.publish.publish_node_write") as mock_publish:
                enrich_cve(driver, client, "CVE-2026-1001", publish=False)
            mock_publish.assert_not_called()

            # ...and the graph write still happened, so this is a suppressed
            # announcement, not a suppressed write.
            with driver.session() as s:
                n = s.run(
                    "MATCH (:CVE {cve_id:'CVE-2026-1001'})-[:MATCHES]->(m:CPEMatch) "
                    "RETURN count(m) AS n"
                ).single()["n"]
            assert n >= 1
        finally:
            self._cleanup(driver)
