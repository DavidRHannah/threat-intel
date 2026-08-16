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
