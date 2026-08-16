from src.assets.matcher import match_asset


def test_match_asset_creates_affects_edge_for_range_hit(driver):
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-8001'}) "
            "MERGE (m:CPEMatch {match_criteria_id:'MC-A'}) "
            "SET m.vendor='cisco', m.product='ios xe', m.version=null, "
            "  m.version_start_including='17.3.0', m.version_start_excluding=null, "
            "  m.version_end_including=null, m.version_end_excluding='17.3.5', m.vulnerable=true "
            "MERGE (c)-[:MATCHES]->(m)"
        ).consume()
        asset = {"asset_key": "cisco::ios xe::17.3.1", "vendor": "cisco", "product": "ios xe", "version": "17.3.1"}
        s.run("MERGE (a:Asset {asset_key:$k}) SET a += $props", k=asset["asset_key"], props=asset).consume()

        hits = s.execute_write(lambda tx: match_asset(tx, asset=asset))
        assert hits == ["MC-A"]
        row = s.run(
            "MATCH (:CVE {cve_id:'CVE-2026-8001'})-[r:AFFECTS]->(:Asset {asset_key:$k}) RETURN r.matched_via AS mv",
            k=asset["asset_key"],
        ).single()
        assert row["mv"] == "MC-A"
    with driver.session() as s:
        s.run("MATCH (c:CVE {cve_id:'CVE-2026-8001'}) DETACH DELETE c").consume()
        s.run("MATCH (m:CPEMatch {match_criteria_id:'MC-A'}) DETACH DELETE m").consume()
        s.run("MATCH (a:Asset {asset_key:$k}) DETACH DELETE a", k=asset["asset_key"]).consume()


def test_match_asset_skips_out_of_range_version(driver):
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-8002'}) "
            "MERGE (m:CPEMatch {match_criteria_id:'MC-B'}) "
            "SET m.vendor='acme', m.product='x', "
            "  m.version='1.0.0', m.version_start_including=null, m.version_start_excluding=null, "
            "  m.version_end_including=null, m.version_end_excluding=null, m.vulnerable=true "
            "MERGE (c)-[:MATCHES]->(m)"
        ).consume()
        asset = {"asset_key": "acme::x::2.0.0", "vendor": "acme", "product": "x", "version": "2.0.0"}
        s.run("MERGE (a:Asset {asset_key:$k}) SET a += $props", k=asset["asset_key"], props=asset).consume()
        hits = s.execute_write(lambda tx: match_asset(tx, asset=asset))
        assert hits == []
    with driver.session() as s:
        s.run("MATCH (c:CVE {cve_id:'CVE-2026-8002'}) DETACH DELETE c").consume()
        s.run("MATCH (m:CPEMatch {match_criteria_id:'MC-B'}) DETACH DELETE m").consume()
        s.run("MATCH (a:Asset {asset_key:$k}) DETACH DELETE a", k=asset["asset_key"]).consume()
