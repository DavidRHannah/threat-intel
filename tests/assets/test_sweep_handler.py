from src.assets.sweep_handler import handler


def test_sweep_processes_multiple_pages(driver, monkeypatch):
    monkeypatch.setattr("src.assets.sweep_handler.get_driver", lambda: driver)
    monkeypatch.setattr("src.assets.sweep_handler._batch_size", lambda: 1)
    with driver.session() as s:
        for i in range(3):
            s.run(
                "MERGE (a:Asset {asset_key:$k, vendor:'acme', product:'x', version:'1.0.0'})",
                k=f"acme::x::1.0.0-{i}",
            ).consume()
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-8200'}) "
            "MERGE (m:CPEMatch {match_criteria_id:'MC-SWEEP'}) "
            "SET m += {vendor:'acme', product:'x', version:'1.0.0', "
            "  version_start_including:null, version_start_excluding:null, "
            "  version_end_including:null, version_end_excluding:null, vulnerable:true} "
            "MERGE (c)-[:MATCHES]->(m)"
            # See Task 7's note: MERGE pattern maps reject null values; MERGE on the key
            # alone, then SET the rest.
        ).consume()

    cursor = None
    total = 0
    for _ in range(10):
        result = handler({"cursor": cursor or ""}, None)
        total += result["count"]
        cursor = result["cursor"] or None
        if result["done"]:
            break
    assert total == 3  # all three assets reconciled across pages, batch_size=1

    with driver.session() as s:
        n = s.run(
            "MATCH (:CVE {cve_id:'CVE-2026-8200'})-[:AFFECTS]->(:Asset) RETURN count(*) AS n"
        ).single()["n"]
        assert n == 3
    with driver.session() as s:
        s.run("MATCH (c:CVE {cve_id:'CVE-2026-8200'}) DETACH DELETE c").consume()
        s.run("MATCH (m:CPEMatch {match_criteria_id:'MC-SWEEP'}) DETACH DELETE m").consume()
        s.run("MATCH (a:Asset) WHERE a.asset_key STARTS WITH 'acme::x::1.0.0-' DETACH DELETE a").consume()


def test_sweep_retracts_an_affects_edge_whose_match_no_longer_holds(driver, monkeypatch):
    """Final-review finding #3. The sweep is the FULL reconciliation, but it only ever
    wrote AFFECTS edges -- an edge whose match stopped holding (NVD flips `vulnerable`
    to false, narrows a range, or drops the cpeMatch) was never removed by anything,
    since the event path also only writes. Mirrors `resync_categorized_as`'s
    existing/wanted/to_delete diffing.
    """
    monkeypatch.setattr("src.assets.sweep_handler.get_driver", lambda: driver)
    with driver.session() as s:
        s.run(
            "MERGE (a:Asset {asset_key:'acme::r::1.0.0'}) "
            "SET a += {vendor:'acme', product:'r', version:'1.0.0'} "
            # STILL matching: exact pin on the asset's own version.
            "MERGE (m1:CPEMatch {match_criteria_id:'MC-STILL'}) "
            "SET m1 += {vendor:'acme', product:'r', version:'1.0.0', "
            "  version_start_including:null, version_start_excluding:null, "
            "  version_end_including:null, version_end_excluding:null, vulnerable:true} "
            "MERGE (c1:CVE {cve_id:'CVE-2026-8300'}) MERGE (c1)-[:MATCHES]->(m1) "
            # NO LONGER matching: NVD flipped `vulnerable` to false.
            "MERGE (m2:CPEMatch {match_criteria_id:'MC-GONE'}) "
            "SET m2 += {vendor:'acme', product:'r', version:'1.0.0', "
            "  version_start_including:null, version_start_excluding:null, "
            "  version_end_including:null, version_end_excluding:null, vulnerable:false} "
            "MERGE (c2:CVE {cve_id:'CVE-2026-8301'}) MERGE (c2)-[:MATCHES]->(m2) "
            # ...but the stale AFFECTS edge from when it did match is still there.
            "MERGE (c2)-[:AFFECTS]->(a) "
            # And one whose CPEMatch was dropped from the CVE entirely.
            "MERGE (c3:CVE {cve_id:'CVE-2026-8302'}) MERGE (c3)-[:AFFECTS]->(a)"
        ).consume()

    try:
        result = handler({}, None)
        assert result["retracted"] == 2
        with driver.session() as s:
            affected = {
                r["cve_id"]
                for r in s.run(
                    "MATCH (c:CVE)-[:AFFECTS]->(:Asset {asset_key:'acme::r::1.0.0'}) "
                    "RETURN c.cve_id AS cve_id"
                )
            }
        assert affected == {"CVE-2026-8300"}
    finally:
        with driver.session() as s:
            s.run(
                "MATCH (c:CVE) WHERE c.cve_id STARTS WITH 'CVE-2026-830' DETACH DELETE c"
            ).consume()
            s.run(
                "MATCH (m:CPEMatch) WHERE m.match_criteria_id IN ['MC-STILL','MC-GONE'] "
                "DETACH DELETE m"
            ).consume()
            s.run("MATCH (a:Asset {asset_key:'acme::r::1.0.0'}) DETACH DELETE a").consume()


class _CountingSession:
    """Wraps one real, kept-open Neo4j session, counting the round trips the sweep
    issues. Same shape as `tests/collection/stix/test_attck_sync.py::_CountingSession`:
    production opens `with driver.session()` blocks, so `__exit__` must NOT close the
    underlying session -- the test closes it once at the end."""

    def __init__(self, session):
        self._session = session
        self.reads = 0
        self.writes = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def execute_read(self, *args, **kwargs):
        self.reads += 1
        return self._session.execute_read(*args, **kwargs)

    def execute_write(self, *args, **kwargs):
        self.writes += 1
        return self._session.execute_write(*args, **kwargs)


def test_sweep_batches_edge_writes_instead_of_one_round_trip_per_match(driver, monkeypatch):
    """Final-review finding #5. The sweep used to do one `execute_write` per asset and,
    inside it, one `merge_relationship` (each with its own `apoc.lock.nodes`) per
    matching CVE -- N assets x M matches sequential round trips against remote AuraDB.
    That is the exact shape of the EPSS / MITRE ATT&CK / ThreatFox production timeouts
    already fixed in this codebase, and the plan's Global Constraints call for batching
    from the start. Pins the COUNT, not just correctness.

    5 assets x 6 CVEs = 30 wanted edges. Batched at 10/round trip this is 3 write round
    trips (plus a retraction pass that has nothing to do, so it issues none) and 3 reads
    (page, candidates, existing edges) -- 6 total, independent of the 30 edges. The old
    per-row shape was 5 execute_writes wrapping 30 merge_relationship round trips.
    """
    monkeypatch.setenv("CROSSROADS_ASSETS_EDGE_BATCH_SIZE", "10")
    from src.common.config import get_config
    get_config.cache_clear()
    monkeypatch.setattr("src.assets.sweep_handler.get_driver", lambda: driver)

    with driver.session() as s:
        for i in range(5):
            s.run(
                "MERGE (a:Asset {asset_key:$k}) "
                "SET a += {vendor:'batchco', product:'p', version:'1.0.0'}",
                k=f"batchco::p::1.0.0-{i}",
            ).consume()
        for j in range(6):
            s.run(
                "MERGE (m:CPEMatch {match_criteria_id:$m}) "
                "SET m += {vendor:'batchco', product:'p', version:'1.0.0', "
                "  version_start_including:null, version_start_excluding:null, "
                "  version_end_including:null, version_end_excluding:null, vulnerable:true} "
                "MERGE (c:CVE {cve_id:$c}) MERGE (c)-[:MATCHES]->(m)",
                m=f"MC-BATCH-{j}", c=f"CVE-2026-84{j:02d}",
            ).consume()

    real_session = driver.session
    underlying = real_session()
    counting = _CountingSession(underlying)
    monkeypatch.setattr(driver, "session", lambda *a, **k: counting)
    try:
        result = handler({}, None)
    finally:
        monkeypatch.setattr(driver, "session", real_session)
        underlying.close()
        get_config.cache_clear()

    assert result["written"] == 30
    assert counting.writes == 3, f"expected 3 batched edge writes, got {counting.writes}"
    assert counting.reads == 3, f"expected 3 reads (page/candidates/existing), got {counting.reads}"

    with driver.session() as s:
        n = s.run(
            "MATCH (:CVE)-[:AFFECTS]->(a:Asset) WHERE a.asset_key STARTS WITH 'batchco::' "
            "RETURN count(*) AS n"
        ).single()["n"]
        assert n == 30
        s.run(
            "MATCH (a:Asset) WHERE a.asset_key STARTS WITH 'batchco::' DETACH DELETE a"
        ).consume()
        s.run(
            "MATCH (m:CPEMatch) WHERE m.match_criteria_id STARTS WITH 'MC-BATCH-' "
            "DETACH DELETE m"
        ).consume()
        s.run(
            "MATCH (c:CVE) WHERE c.cve_id STARTS WITH 'CVE-2026-84' DETACH DELETE c"
        ).consume()
