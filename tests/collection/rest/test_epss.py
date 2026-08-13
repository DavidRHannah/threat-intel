"""Integration tests for EPSS daily batch refresh (L1 Task 10).

Runs against a real local Neo4j (docker compose up -d neo4j). Covers:

- FR-DC-24: the EPSS refresh updates epss_score on existing CVE nodes only and
  never creates CVE nodes for rows in the CSV with no matching graph node.
"""

from pathlib import Path

import pytest

from src.collection.rest.epss import refresh_epss_scores
from src.common.neo4j_driver import close_driver, get_driver
from src.common.schema_bootstrap import bootstrap_schema

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _load_fixture() -> str:
    return (FIXTURES / "epss_sample.csv").read_text()


def _cve_count(driver, cve_id: str) -> int:
    """Count CVE nodes with the given cve_id."""
    with driver.session() as s:
        result = s.run("MATCH (c:CVE {cve_id:$id}) RETURN count(c) AS cnt", id=cve_id)
        return result.single()["cnt"]


def _cve_epss(driver, cve_id: str) -> float | None:
    """Get the epss_score for a CVE, or None if the CVE doesn't exist."""
    with driver.session() as s:
        rec = s.run("MATCH (c:CVE {cve_id:$id}) RETURN c.epss_score AS score", id=cve_id)
        row = rec.single()
    return row["score"] if row else None


@pytest.fixture(autouse=True)
def _clear_config_cache(monkeypatch):
    from src.common import config
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
        # Clean up test fixtures
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
        # Pre-create two CVE nodes: one that's in the EPSS fixture, one that's not.
        s.run(
            "MERGE (a:CVE {cve_id:'CVE-2026-1001'}) SET a.test_fixture = true "
            "MERGE (b:CVE {cve_id:'CVE-2026-2001'}) SET b.test_fixture = true"
        ).consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


def test_refresh_updates_existing_cve_only_never_creates(driver):
    """FR-DC-24: EPSS refresh updates existing CVE nodes only and never creates
    new nodes for CSV rows with no graph match.

    Setup:
      - CVE-2026-1001: exists in graph, also in fixture CSV → should update
      - CVE-2026-2001: exists in graph, NOT in fixture CSV → should not change
      - CVE-2026-1002: in fixture CSV, does NOT exist in graph → should NOT be created

    Assertions:
      - CVE-2026-1001.epss_score updates to 0.95
      - CVE-2026-2001.epss_score remains null (untouched)
      - CVE-2026-1002 remains uncreated (count before == 0, count after == 0)
      - Refresh returns count == 1 (one CVE updated)
    """
    # Verify preconditions.
    assert _cve_count(driver, "CVE-2026-1001") == 1
    assert _cve_count(driver, "CVE-2026-2001") == 1
    assert _cve_count(driver, "CVE-2026-1002") == 0  # not created yet

    # Call refresh with the fixture CSV.
    count = refresh_epss_scores(driver, lambda: _load_fixture())

    # FR-DC-24: existing and matched CVE's epss_score is updated.
    assert _cve_epss(driver, "CVE-2026-1001") == 0.95

    # FR-DC-24: existing but unmatched CVE is untouched.
    assert _cve_epss(driver, "CVE-2026-2001") is None

    # FR-DC-24: no new CVE node is created for CSV row with no graph match.
    assert _cve_count(driver, "CVE-2026-1002") == 0

    # Refresh returns the count of CVEs updated.
    assert count == 1


def test_refresh_batches_writes_instead_of_one_call_per_row(driver, monkeypatch):
    """Regression for a real production bug: the EPSS Step Function always failed with
    Sandbox.Timedout (confirmed live, 2026-08-13 -- only 3/1675 CVEs got scored in a
    300s Lambda run) because the original implementation issued one session.run() per
    CSV row, and the real bulk file has ~200k rows. `refresh_epss_scores` must batch
    its writes (UNWIND per chunk) so the round-trip count is bounded by
    ceil(rows/batch_size), not rows.

    Forces batch_size=2 across 5 rows (3 matching CVEs spanning a batch boundary, 2
    non-matching) to prove both: (a) matches still land correctly across the
    boundary, and (b) the actual number of session.run() calls is batched.
    """
    with driver.session() as s:
        s.run(
            "MERGE (a:CVE {cve_id:'CVE-2026-3001'}) SET a.test_fixture = true "
            "MERGE (b:CVE {cve_id:'CVE-2026-3002'}) SET b.test_fixture = true"
        ).consume()

    csv = (
        "cve,epss\n"
        "CVE-2026-1001,0.11\n"  # matches (pre-created by the `driver` fixture)
        "CVE-2026-3001,0.22\n"  # matches
        "CVE-2026-9001,0.33\n"  # no match
        "CVE-2026-3002,0.44\n"  # matches
        "CVE-2026-9002,0.55\n"  # no match
    )

    call_count = 0
    real_session = driver.session

    class _CountingSession:
        def __init__(self, inner):
            self._inner = inner

        def __enter__(self):
            self._session = self._inner.__enter__()
            return self

        def __exit__(self, *exc_info):
            return self._inner.__exit__(*exc_info)

        def run(self, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            return self._session.run(*args, **kwargs)

    monkeypatch.setattr(driver, "session", lambda *a, **k: _CountingSession(real_session(*a, **k)))

    count = refresh_epss_scores(driver, lambda: csv, batch_size=2)
    # ceil(5 rows / batch_size=2) == 3 round trips, not 5 -- this is the actual fix.
    # Captured immediately after refresh returns, before any verification reads
    # (which also go through the patched driver.session and would inflate this).
    assert call_count == 3

    assert count == 3
    monkeypatch.setattr(driver, "session", real_session)
    assert _cve_epss(driver, "CVE-2026-1001") == 0.11
    assert _cve_epss(driver, "CVE-2026-3001") == 0.22
    assert _cve_epss(driver, "CVE-2026-3002") == 0.44
