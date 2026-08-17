import json

from src.assets.event_handler import handler


def _sns_event(message: dict) -> dict:
    return {"Records": [{"Sns": {"Message": json.dumps(message)}}]}


def test_handler_matches_new_cpe_match_against_existing_assets(driver, monkeypatch):
    monkeypatch.setattr("src.assets.event_handler.get_driver", lambda: driver)
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-8100'}) "
            "MERGE (m:CPEMatch {match_criteria_id:'MC-EVT'}) "
            "SET m += {vendor:'acme', product:'x', version:'1.0.0', "
            "  version_start_including:null, version_start_excluding:null, "
            "  version_end_including:null, version_end_excluding:null, vulnerable:true} "
            "MERGE (c)-[:MATCHES]->(m)"
        ).consume()
        # Note: Neo4j rejects null values inside a MERGE pattern map
        # ("Cannot merge ... because of null property value") -- MERGE on the key alone,
        # then SET the remaining properties (SET allows null). Task 6 hit and fixed this
        # exact issue in its own test fixtures; apply the same MERGE-then-SET split here.
        s.run(
            "MERGE (a:Asset {asset_key:'acme::x::1.0.0', vendor:'acme', product:'x', version:'1.0.0'})"
        ).consume()

    result = handler(
        _sns_event({
            "message_type": "node_write", "label": "CPEMatch",
            "key": {"match_criteria_id": "MC-EVT"}, "changed_fields": ["vulnerable"],
        }),
        None,
    )
    assert result["processed"] == 1
    with driver.session() as s:
        row = s.run(
            "MATCH (:CVE {cve_id:'CVE-2026-8100'})-[:AFFECTS]->(:Asset {asset_key:'acme::x::1.0.0'}) RETURN count(*) AS n"
        ).single()
        assert row["n"] == 1
    with driver.session() as s:
        s.run("MATCH (c:CVE {cve_id:'CVE-2026-8100'}) DETACH DELETE c").consume()
        s.run("MATCH (m:CPEMatch {match_criteria_id:'MC-EVT'}) DETACH DELETE m").consume()
        s.run("MATCH (a:Asset {asset_key:'acme::x::1.0.0'}) DETACH DELETE a").consume()


def test_handler_writes_affects_for_every_cve_sharing_one_cpe_match(driver, monkeypatch):
    """Final-review finding #2 (live-reproduced). `_match_and_assets` used `LIMIT 1` on
    the CVE lookup, but a `matchCriteriaId` is deliberately SHARED across CVEs (see
    `tests/common/graph/test_structural_edges.py::
    test_resync_matches_removes_stale_edge_but_not_the_shared_node`). Only one of the
    CVEs got an AFFECTS edge; the rest were silently dropped and the handler still
    reported success.
    """
    monkeypatch.setattr("src.assets.event_handler.get_driver", lambda: driver)
    with driver.session() as s:
        s.run(
            "MERGE (m:CPEMatch {match_criteria_id:'MC-SHARED'}) "
            "SET m += {vendor:'acme', product:'x', version:'1.0.0', "
            "  version_start_including:null, version_start_excluding:null, "
            "  version_end_including:null, version_end_excluding:null, vulnerable:true} "
            "MERGE (c1:CVE {cve_id:'CVE-2026-8110'}) MERGE (c1)-[:MATCHES]->(m) "
            "MERGE (c2:CVE {cve_id:'CVE-2026-8111'}) MERGE (c2)-[:MATCHES]->(m)"
        ).consume()
        s.run(
            "MERGE (a:Asset {asset_key:'acme::x::1.0.0'}) "
            "SET a += {vendor:'acme', product:'x', version:'1.0.0'}"
        ).consume()

    try:
        result = handler(
            _sns_event({
                "message_type": "node_write", "label": "CPEMatch",
                "key": {"match_criteria_id": "MC-SHARED"}, "changed_fields": ["vulnerable"],
            }),
            None,
        )
        assert result["processed"] == 1
        with driver.session() as s:
            affected = {
                r["cve_id"]
                for r in s.run(
                    "MATCH (c:CVE)-[:AFFECTS]->(:Asset {asset_key:'acme::x::1.0.0'}) "
                    "RETURN c.cve_id AS cve_id"
                )
            }
        assert affected == {"CVE-2026-8110", "CVE-2026-8111"}
    finally:
        with driver.session() as s:
            s.run(
                "MATCH (c:CVE) WHERE c.cve_id IN ['CVE-2026-8110','CVE-2026-8111'] "
                "DETACH DELETE c"
            ).consume()
            s.run("MATCH (m:CPEMatch {match_criteria_id:'MC-SHARED'}) DETACH DELETE m").consume()
            s.run("MATCH (a:Asset {asset_key:'acme::x::1.0.0'}) DETACH DELETE a").consume()
