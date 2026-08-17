from src.common.schema_bootstrap import bootstrap_schema

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


def _plan_operators(plan) -> set[str]:
    ops = {plan["operatorType"].split("@")[0]}
    for child in plan.get("children", []):
        ops |= _plan_operators(child)
    return ops


def test_candidate_lookup_uses_an_index_seek_not_a_label_scan(driver):
    """Final-review finding #4. `candidate_matches_for` filtered with
    `toLower(m.vendor) = toLower($vendor)` -- a function call on the property, which
    cannot use an index even once one exists -- and no CPEMatch(vendor, product) index
    existed at all, so every match event and every sweep page scanned the largest label
    in the graph. Vendor/product are now case-folded at WRITE time (`_split_cpe`,
    `create_asset`) and compared with plain equality.

    Asserts the PLAN, against real Neo4j: reasoning about index usage is exactly the
    class of claim this repo requires a probe for.
    """
    bootstrap_schema(driver)
    with driver.session() as s:
        new_plan = s.run(
            "EXPLAIN MATCH (m:CPEMatch {vendor: $vendor, product: $product})<-[:MATCHES]-(c:CVE) "
            "RETURN c.cve_id",
            vendor="acme", product="x",
        ).consume().plan
        old_plan = s.run(
            "EXPLAIN MATCH (c:CVE)-[:MATCHES]->(m:CPEMatch) "
            "WHERE toLower(m.vendor) = toLower($vendor) AND toLower(m.product) = toLower($product) "
            "RETURN c.cve_id",
            vendor="acme", product="x",
        ).consume().plan
        asset_plan = s.run(
            "EXPLAIN MATCH (a:Asset {vendor: $vendor, product: $product}) RETURN a.asset_key",
            vendor="acme", product="x",
        ).consume().plan

    new_ops = _plan_operators(new_plan)
    assert any(op.startswith("NodeIndexSeek") for op in new_ops), new_ops
    assert "NodeByLabelScan" not in new_ops and "AllNodesScan" not in new_ops

    # The shape this replaced: no index seek anywhere, a full relationship-type scan.
    old_ops = _plan_operators(old_plan)
    assert not any(op.startswith("NodeIndexSeek") for op in old_ops), old_ops

    asset_ops = _plan_operators(asset_plan)
    assert any(op.startswith("NodeIndexSeek") for op in asset_ops), asset_ops
