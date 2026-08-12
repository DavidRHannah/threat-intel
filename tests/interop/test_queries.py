import datetime as dt_module
from datetime import datetime, timezone

import pytest
from moto import mock_aws
from neo4j.time import DateTime as Neo4jDateTime

from src.common.config import get_config
from src.common.neo4j_driver import close_driver, get_driver
from src.interop.queries import (
    fetch_edges_page,
    fetch_nodes_page,
    fetch_revoked_nodes_page,
    mark_exported,
    scan_revoked_tombstones,
)


@pytest.fixture
def driver():
    """Local fixture, same convention as every other Neo4j-backed test file in this
    repo -- there is no shared conftest.py. Every node/edge this file creates must be
    tagged `test_fixture: true` so this cleanup finds it."""
    d = get_driver()
    d.verify_connectivity()
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


def test_fetch_nodes_page_filters_by_added_after(driver):
    old = datetime(2026, 1, 1, tzinfo=timezone.utc)
    new = datetime(2026, 8, 1, tzinfo=timezone.utc)
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-OLD', confidence: 0.9, last_updated: $old, "
            "test_fixture: true})"
            "CREATE (:CVE {cve_id: 'CVE-NEW', confidence: 0.9, last_updated: $new, "
            "test_fixture: true})",
            old=old, new=new,
        )

    with driver.session() as session:
        rows, cursor = session.execute_read(
            lambda tx: fetch_nodes_page(
                tx, cursor=None, batch_size=10, floor=0.3,
                added_after=datetime(2026, 6, 1, tzinfo=timezone.utc),
            )
        )
    cve_ids = {r["props"]["cve_id"] for r in rows}
    assert cve_ids == {"CVE-NEW"}


def test_fetch_nodes_page_excludes_provisional_and_below_floor(driver):
    ts = datetime(2026, 8, 1, tzinfo=timezone.utc)
    with driver.session() as session:
        session.run(
            "CREATE (:ThreatActor:Provisional "
            "{merge_key: 'x', confidence: 0.9, last_updated: $ts, test_fixture: true}) "
            "CREATE (:ThreatActor {merge_key: 'y', confidence: 0.1, last_updated: $ts, "
            "test_fixture: true})",
            ts=ts,
        )

    with driver.session() as session:
        rows, _ = session.execute_read(
            lambda tx: fetch_nodes_page(
                tx, cursor=None, batch_size=10, floor=0.3, added_after=None,
            )
        )
    keys = {r["props"].get("merge_key") for r in rows if r["label"] == "ThreatActor"}
    assert "x" not in keys
    assert "y" not in keys


def test_fetch_nodes_page_excludes_revoked(driver):
    """C3: a node with `revoked: true` must not also come back through the normal
    export page -- fetch_revoked_nodes_page already serves it as a revoked stub, so a
    consumer that sees it in BOTH places gets the same STIX id as a full SDO and a
    tombstone in one response. Only the withdrawal sweep sets `revoked`; recovery (a
    later rescan pushing confidence back up) does not clear it, so exclusion here is
    what keeps the two views from colliding, not a clearing step on the write side."""
    ts = datetime(2026, 8, 1, tzinfo=timezone.utc)
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-REVOKED', confidence: 0.9, revoked: true, "
            "last_updated: $ts, test_fixture: true}) "
            "CREATE (:CVE {cve_id: 'CVE-LIVE', confidence: 0.9, last_updated: $ts, "
            "test_fixture: true})",
            ts=ts,
        )

    with driver.session() as session:
        rows, _ = session.execute_read(
            lambda tx: fetch_nodes_page(
                tx, cursor=None, batch_size=10, floor=0.3, added_after=None,
            )
        )
    cve_ids = {r["props"]["cve_id"] for r in rows if r["label"] == "CVE"}
    assert cve_ids == {"CVE-LIVE"}


def test_fetch_nodes_page_paginates_multi_page(driver):
    """A one-page test proves nothing for pagination -- batch size 1, seed 3 rows."""
    ts = datetime(2026, 8, 1, tzinfo=timezone.utc)
    with driver.session() as session:
        for i in range(3):
            session.run(
                "CREATE (:CVE {cve_id: $id, confidence: 0.9, last_updated: $ts, "
                "test_fixture: true})",
                id=f"CVE-{i}", ts=ts,
            )

    seen = []
    cursor = None
    for _ in range(10):
        with driver.session() as session:
            rows, cursor = session.execute_read(
                lambda tx: fetch_nodes_page(
                    tx, cursor=cursor, batch_size=1, floor=0.3, added_after=None,
                )
            )
        seen.extend(r["props"]["cve_id"] for r in rows)
        if cursor is None:
            break
    assert sorted(seen) == ["CVE-0", "CVE-1", "CVE-2"]


def test_mark_exported_sets_flag(driver):
    with driver.session() as session:
        session.run("CREATE (:CVE {cve_id: 'CVE-2026-1234', test_fixture: true})")
        session.execute_write(mark_exported, "CVE", {"cve_id": "CVE-2026-1234"})
        record = session.run(
            "MATCH (c:CVE {cve_id: 'CVE-2026-1234'}) RETURN c.exported AS e"
        ).single()
    assert record["e"] is True


def test_fetch_edges_page_excludes_below_floor(driver):
    ts = datetime(2026, 8, 1, tzinfo=timezone.utc)
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-2026-1', test_fixture: true})"
            "-[:EXPLOITED_BY {confidence: 0.1, last_updated: $ts}]->"
            "(:ThreatActor {merge_key: 'lazarus', test_fixture: true})",
            ts=ts,
        )

    with driver.session() as session:
        rows, _ = session.execute_read(
            lambda tx: fetch_edges_page(
                tx, cursor=None, batch_size=10, floor=0.3, added_after=None,
            )
        )
    assert rows == []


def test_fetch_edges_page_normalizes_neo4j_datetimes_to_native(driver):
    """`properties(a)`/`properties(b)`/`properties(r)` come back from the driver as
    `neo4j.time.DateTime`, not a native `datetime.datetime` -- `src/interop/mapping.py`
    (and any future caller, e.g. the Task 3.1 withdrawal sweep) assumes native. Prove
    `fetch_edges_page` normalizes ALL THREE property dicts (edge, start node, end
    node), not just the node path already covered by
    `test_fetch_nodes_page_filters_by_added_after` et al."""
    ts = datetime(2026, 8, 1, tzinfo=timezone.utc)
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-2026-9', confidence: 0.9, last_updated: $ts, "
            "test_fixture: true})"
            "-[:EXPLOITED_BY {confidence: 0.9, last_updated: $ts}]->"
            "(:ThreatActor {merge_key: 'lazarus-dt', confidence: 0.9, last_updated: $ts, "
            "test_fixture: true})",
            ts=ts,
        )

    with driver.session() as session:
        rows, _ = session.execute_read(
            lambda tx: fetch_edges_page(
                tx, cursor=None, batch_size=10, floor=0.3, added_after=None,
            )
        )
    matching = [r for r in rows if r["start_props"].get("cve_id") == "CVE-2026-9"]
    assert len(matching) == 1
    row = matching[0]
    for props in (row["props"], row["start_props"], row["end_props"]):
        value = props["last_updated"]
        assert type(value) is dt_module.datetime
        assert not isinstance(value, Neo4jDateTime)


def test_fetch_revoked_nodes_page_ignores_confidence(driver):
    ts = datetime(2026, 8, 1, tzinfo=timezone.utc)
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-2026-1', confidence: 0.01, revoked: true, "
            "exported: false, last_updated: $ts, test_fixture: true})",
            ts=ts,
        )

    with driver.session() as session:
        rows, _ = session.execute_read(
            lambda tx: fetch_revoked_nodes_page(
                tx, cursor=None, batch_size=10, added_after=None,
            )
        )
    assert [r["props"]["cve_id"] for r in rows] == ["CVE-2026-1"]


def test_fetch_revoked_nodes_page_excludes_never_revoked(driver):
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-2026-1', confidence: 0.9, test_fixture: true})"
        )

    with driver.session() as session:
        rows, _ = session.execute_read(
            lambda tx: fetch_revoked_nodes_page(
                tx, cursor=None, batch_size=10, added_after=None,
            )
        )
    assert rows == []


def test_scan_revoked_tombstones_local_env_missing_table_returns_empty(monkeypatch):
    """`get_config` raises the SAME `KeyError` for "unconfigured in local dev" as it
    does for "genuinely missing SSM parameter in dev/prod" -- this test pins that the
    LOCAL case degrades to an empty list (the table's env-var wiring is out of this
    task's scope, so local dev without it must not crash the whole Objects endpoint)."""
    get_config.cache_clear()
    monkeypatch.setenv("CROSSROADS_ENV", "local")
    monkeypatch.delenv("CROSSROADS_REVOKED_STIX_IDS_TABLE_NAME", raising=False)
    try:
        assert scan_revoked_tombstones(added_after=None) == []
    finally:
        get_config.cache_clear()


@mock_aws
def test_scan_revoked_tombstones_non_local_env_missing_table_raises(monkeypatch):
    """Same missing-config shape as the local test above, but in a non-local env
    (`dev`) -- a genuinely missing SSM parameter must RAISE, not silently return `[]`,
    since this repo has no CloudWatch alarms anywhere and a swallowed KeyError here
    would mask a real deploy misconfiguration as "zero tombstones" forever."""
    get_config.cache_clear()
    monkeypatch.setenv("CROSSROADS_ENV", "dev")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("CROSSROADS_REVOKED_STIX_IDS_TABLE_NAME", raising=False)
    try:
        with pytest.raises(KeyError):
            scan_revoked_tombstones(added_after=None)
    finally:
        get_config.cache_clear()
