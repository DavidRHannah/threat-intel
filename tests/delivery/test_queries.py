# tests/delivery/test_queries.py
from datetime import datetime, timedelta, timezone

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.delivery.queries import (
    entity_short_type,
    entity_subgraph_type,
    fetch_cves_for_all_assets,
    fetch_cves_for_asset,
    fetch_known_vendor_products,
    fetch_recent_stories,
    fetch_stats,
    fetch_subgraph,
    fetch_top_actors,
    fetch_top_campaigns,
    fetch_top_cves,
    fetch_top_malware,
)


@pytest.fixture
def driver():
    d = get_driver()
    d.verify_connectivity()
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


def test_fetch_top_cves_orders_by_severity_score_desc(driver):
    """FR-DEL-01: top CVEs ordered by severity_score, no graph writes performed."""
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-LOW', severity_score: 0.2, severity_band: 'low', "
            "  cvss_score: 3.0, epss_score: 0.01, exploited_in_wild: false, "
            "  relevance_score: 0.1, description: 'low', published_date: '2026-01-01', "
            "  test_fixture: true})"
            "CREATE (:CVE {cve_id: 'CVE-CRIT', severity_score: 0.9, severity_band: 'critical', "
            "  cvss_score: 9.8, epss_score: 0.9, exploited_in_wild: true, "
            "  relevance_score: 0.8, description: 'crit', published_date: '2026-02-01', "
            "  test_fixture: true})"
        )
    with driver.session() as session:
        rows = session.execute_read(lambda tx: fetch_top_cves(tx, limit=10))
    assert [r["cve_id"] for r in rows] == ["CVE-CRIT", "CVE-LOW"]
    assert rows[0]["severity_band"] == "critical"
    assert rows[0]["exploited_in_wild"] is True


def test_fetch_top_cves_null_severity_score_sorts_last(driver):
    """A CVE with no severity_score yet (e.g. awaiting NVD enrichment) must not outrank
    real scored CVEs -- Neo4j's default `ORDER BY x DESC` sorts NULL first, which would
    otherwise put every unscored CVE at the top of "Top Threats" (found via manual
    smoke test against the real graph, where 14 originally-extracted CVEs carry
    epss_score but not severity_score, per CLAUDE.md's Current State)."""
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-UNSCORED', severity_score: null, "
            "  cvss_score: null, epss_score: 0.02, exploited_in_wild: false, "
            "  relevance_score: 0.1, description: 'unscored', published_date: '2026-01-01', "
            "  test_fixture: true})"
            "CREATE (:CVE {cve_id: 'CVE-CRIT', severity_score: 0.9, severity_band: 'critical', "
            "  cvss_score: 9.8, epss_score: 0.9, exploited_in_wild: true, "
            "  relevance_score: 0.8, description: 'crit', published_date: '2026-02-01', "
            "  test_fixture: true})"
        )
    with driver.session() as session:
        rows = session.execute_read(lambda tx: fetch_top_cves(tx, limit=10))
    assert [r["cve_id"] for r in rows] == ["CVE-CRIT", "CVE-UNSCORED"]


def test_fetch_top_cves_respects_limit(driver):
    with driver.session() as session:
        for i in range(3):
            session.run(
                "CREATE (:CVE {cve_id: $id, severity_score: $s, description: '', "
                "  cvss_score: 5.0, epss_score: 0.1, exploited_in_wild: false, "
                "  relevance_score: 0.1, severity_band: 'medium', "
                "  published_date: '2026-01-01', test_fixture: true})",
                id=f"CVE-{i}", s=float(i),
            )
    with driver.session() as session:
        rows = session.execute_read(lambda tx: fetch_top_cves(tx, limit=2))
    assert len(rows) == 2


def test_fetch_top_actors_orders_by_relevance_desc_and_excludes_revoked(driver):
    with driver.session() as session:
        session.run(
            "CREATE (:ThreatActor {merge_key: 'a-low', name: 'Low', relevance_score: 0.2, "
            "  test_fixture: true})"
            "CREATE (:ThreatActor {merge_key: 'a-high', name: 'High', relevance_score: 0.9, "
            "  test_fixture: true})"
            "CREATE (:ThreatActor {merge_key: 'a-revoked', name: 'Revoked', "
            "  relevance_score: 0.99, is_revoked: true, test_fixture: true})"
        )
    with driver.session() as session:
        rows = session.execute_read(lambda tx: fetch_top_actors(tx, limit=10))
    assert [r["name"] for r in rows] == ["High", "Low"]


def test_fetch_top_malware_orders_by_relevance_desc(driver):
    with driver.session() as session:
        session.run(
            "CREATE (:MalwareFamily {merge_key: 'm-low', name: 'Low', relevance_score: 0.3, "
            "  malware_type: 'tool', test_fixture: true})"
            "CREATE (:MalwareFamily {merge_key: 'm-high', name: 'High', relevance_score: 0.7, "
            "  malware_type: 'rat', test_fixture: true})"
        )
    with driver.session() as session:
        rows = session.execute_read(lambda tx: fetch_top_malware(tx, limit=10))
    assert [r["name"] for r in rows] == ["High", "Low"]


def test_fetch_top_campaigns_orders_by_relevance_desc_and_excludes_revoked(driver):
    with driver.session() as session:
        session.run(
            "CREATE (:Campaign {merge_key: 'c-low', name: 'Low', relevance_score: 0.2, "
            "  start_date: '2021-01-01', end_date: '2021-06-01', test_fixture: true})"
            "CREATE (:Campaign {merge_key: 'c-high', name: 'High', relevance_score: 0.8, "
            "  start_date: '2022-01-01', end_date: null, test_fixture: true})"
            "CREATE (:Campaign {merge_key: 'c-revoked', name: 'Revoked', "
            "  relevance_score: 0.99, is_revoked: true, test_fixture: true})"
        )
    with driver.session() as session:
        rows = session.execute_read(lambda tx: fetch_top_campaigns(tx, limit=10))
    assert [r["name"] for r in rows] == ["High", "Low"]


def test_fetch_stats_counts_and_severity_distribution(driver):
    """FR-DEL-09: this read must not create or modify any threat node/edge."""
    now = datetime.now(timezone.utc)
    with driver.session() as session:
        # fetched_at is written as a plain Python `.isoformat()` string in production
        # (src/collection/rss/poller.py's `_default_fetched_at`), never a Cypher
        # `datetime()` value -- match that shape here or the comparison-against-string
        # bug this test exists to pin would go undetected.
        session.run(
            "CREATE (:CVE {cve_id: 'C1', severity_band: 'critical', exploited_in_wild: true, "
            "  test_fixture: true})"
            "CREATE (:CVE {cve_id: 'C2', severity_band: 'low', exploited_in_wild: false, "
            "  test_fixture: true})"
            "CREATE (:Article {source_guid_key: 'a1', fetched_at: $now, "
            "  test_fixture: true})",
            now=now.isoformat(),
        )
        before_count = session.run(
            "MATCH (n) WHERE n.test_fixture = true RETURN count(n) AS c"
        ).single()["c"]

    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    with driver.session() as session:
        stats = session.execute_read(
            lambda tx: fetch_stats(
                tx, today_start=today_start.isoformat(),
                week_start=(today_start - timedelta(days=7)).isoformat(),
            )
        )
        after_count = session.run(
            "MATCH (n) WHERE n.test_fixture = true RETURN count(n) AS c"
        ).single()["c"]

    assert stats["total_cves"] >= 2
    assert stats["critical_cves"] >= 1
    assert stats["active_exploits"] >= 1
    assert stats["articles_today"] >= 1
    assert after_count == before_count  # no writes


def test_fetch_recent_stories_returns_representative_with_entities(driver):
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-STORY', test_fixture: true})"
            "CREATE (a:Article {source_guid_key: 'a-rep', title: 'Headline', "
            "  story_cluster_id: 'sc-1', is_cluster_representative: true, "
            "  dedup_cluster_size: 3, published_at: datetime('2026-08-01T00:00:00Z'), "
            "  test_fixture: true})"
            "WITH a "
            "MATCH (c:CVE {cve_id: 'CVE-STORY'}) "
            "CREATE (a)-[:MENTIONS {test_fixture: true}]->(c)"
        )
    with driver.session() as session:
        rows = session.execute_read(lambda tx: fetch_recent_stories(tx, limit=10))
    assert rows[0]["headline"] == "Headline"
    assert rows[0]["article_count"] == 3
    assert rows[0]["entities"][0]["type"] == "cve"
    assert rows[0]["entities"][0]["id"] == "CVE-STORY"


def test_fetch_recent_stories_orders_correctly_across_mixed_timestamp_formats(driver):
    """`Article.published_at` is not a uniform format in production -- some rows carry
    ISO 8601, others an RFC 822 string straight from feedparser (see
    src/nlp/dedup/similarity.py's `_parse_timestamp` docstring). A plain Cypher
    `ORDER BY a.published_at DESC` sorts lexicographically and would misorder this
    mix; this pins that the real (chronological) order still comes out right."""
    with driver.session() as session:
        session.run(
            "CREATE (:Article {source_guid_key: 'older', title: 'Older', "
            "  story_cluster_id: 'sc-older', is_cluster_representative: true, "
            "  dedup_cluster_size: 1, published_at: 'Mon, 01 Jun 2026 00:00:00 GMT', "
            "  test_fixture: true})"
            "CREATE (:Article {source_guid_key: 'newer', title: 'Newer', "
            "  story_cluster_id: 'sc-newer', is_cluster_representative: true, "
            "  dedup_cluster_size: 1, published_at: '2026-08-01T00:00:00+00:00', "
            "  test_fixture: true})"
        )
    with driver.session() as session:
        rows = session.execute_read(lambda tx: fetch_recent_stories(tx, limit=10))
    headlines = [r["headline"] for r in rows]
    assert headlines.index("Newer") < headlines.index("Older")


def test_fetch_subgraph_returns_node_and_neighbors(driver):
    with driver.session() as session:
        session.run(
            "CREATE (c:CVE {cve_id: 'CVE-EGO', severity_score: 0.9, test_fixture: true})"
            "CREATE (a:ThreatActor {merge_key: 'ego-actor', name: 'Ego Actor', "
            "  relevance_score: 0.8, test_fixture: true})"
            "WITH c, a "
            "CREATE (c)-[:EXPLOITED_BY {confidence: 0.9, origin: 'authoritative', "
            "  test_fixture: true}]->(a)"
        )
        element_id = session.run(
            "MATCH (c:CVE {cve_id: 'CVE-EGO'}) RETURN elementId(c) AS id"
        ).single()["id"]

    with driver.session() as session:
        result = session.execute_read(lambda tx: fetch_subgraph(tx, element_id=element_id))
    assert result["node"]["props"]["cve_id"] == "CVE-EGO"
    assert result["node"]["type"] == "cve"
    assert len(result["neighbors"]) == 1
    assert result["neighbors"][0]["type"] == "threat_actor"
    assert result["edges"][0]["type"] == "EXPLOITED_BY"


def test_fetch_subgraph_node_carries_its_element_id(driver):
    """FR-DL-06: every edge endpoint must resolve to a returned node.

    The central node was returned without an `id`, so the graph renderer built it
    with `id: undefined` while the edges still referenced its real elementId --
    cytoscape rejects an edge whose source does not exist and the page blanked.
    """
    with driver.session() as session:
        session.run(
            "CREATE (c:CVE {cve_id: 'CVE-EGOID', severity_score: 0.9, test_fixture: true})"
            "CREATE (w:CWE {cwe_id: 'CWE-20', test_fixture: true})"
            "WITH c, w "
            "CREATE (c)-[:CATEGORIZED_AS {test_fixture: true}]->(w)"
        )
        element_id = session.run(
            "MATCH (c:CVE {cve_id: 'CVE-EGOID'}) RETURN elementId(c) AS id"
        ).single()["id"]

    with driver.session() as session:
        result = session.execute_read(lambda tx: fetch_subgraph(tx, element_id=element_id))

    assert result["node"]["id"] == element_id
    known_ids = {result["node"]["id"]} | {n["id"] for n in result["neighbors"]}
    for edge in result["edges"]:
        assert edge["source"] in known_ids
        assert edge["target"] in known_ids


def test_fetch_subgraph_types_cwe_neighbours(driver):
    """CWE is the most common CVE neighbour in production but had no type mapping."""
    with driver.session() as session:
        session.run(
            "CREATE (c:CVE {cve_id: 'CVE-EGOCWE', test_fixture: true})"
            "CREATE (w:CWE {cwe_id: 'CWE-79', test_fixture: true})"
            "WITH c, w "
            "CREATE (c)-[:CATEGORIZED_AS {test_fixture: true}]->(w)"
        )
        element_id = session.run(
            "MATCH (c:CVE {cve_id: 'CVE-EGOCWE'}) RETURN elementId(c) AS id"
        ).single()["id"]

    with driver.session() as session:
        result = session.execute_read(lambda tx: fetch_subgraph(tx, element_id=element_id))

    assert result["neighbors"][0]["type"] == "cwe"


def test_entity_short_type_and_subgraph_type_mappings():
    assert entity_short_type(["CVE"]) == "cve"
    assert entity_short_type(["ThreatActor"]) == "actor"
    assert entity_short_type(["MalwareFamily"]) == "malware"
    assert entity_short_type(["TTP"]) == "ttp"
    assert entity_short_type(["Unknown"]) is None
    assert entity_subgraph_type(["ThreatActor"]) == "threat_actor"
    assert entity_subgraph_type(["MalwareFamily"]) == "malware_family"
    assert entity_subgraph_type(["IOC"]) == "ioc"
    assert entity_subgraph_type(["Article"]) == "article"
    assert entity_subgraph_type(["CWE"]) == "cwe"


def test_fetch_cves_for_asset_orders_by_severity(driver):
    with driver.session() as s:
        s.run(
            "MERGE (a:Asset {asset_key:'k1', vendor:'acme', product:'x', version:'1.0'}) "
            "MERGE (c1:CVE {cve_id:'CVE-A', severity_score:0.9}) "
            "MERGE (c2:CVE {cve_id:'CVE-B', severity_score:0.3}) "
            "MERGE (c1)-[:AFFECTS]->(a) MERGE (c2)-[:AFFECTS]->(a)"
        ).consume()
        rows = s.execute_read(lambda tx: fetch_cves_for_asset(tx, asset_key="k1"))
        assert [r["cve_id"] for r in rows] == ["CVE-A", "CVE-B"]
    with driver.session() as s:
        s.run("MATCH (a:Asset {asset_key:'k1'}) DETACH DELETE a").consume()
        s.run("MATCH (c:CVE) WHERE c.cve_id IN ['CVE-A','CVE-B'] DETACH DELETE c").consume()


def test_fetch_cves_for_all_assets_dedupes(driver):
    with driver.session() as s:
        s.run(
            "MERGE (a1:Asset {asset_key:'k2', vendor:'acme', product:'y', version:'1.0'}) "
            "MERGE (a2:Asset {asset_key:'k3', vendor:'acme', product:'z', version:'1.0'}) "
            "MERGE (c:CVE {cve_id:'CVE-C', severity_score:0.5}) "
            "MERGE (c)-[:AFFECTS]->(a1) MERGE (c)-[:AFFECTS]->(a2)"
        ).consume()
        rows = s.execute_read(fetch_cves_for_all_assets)
        assert len([r for r in rows if r["cve_id"] == "CVE-C"]) == 1
    with driver.session() as s:
        s.run("MATCH (a:Asset) WHERE a.asset_key IN ['k2','k3'] DETACH DELETE a").consume()
        s.run("MATCH (c:CVE {cve_id:'CVE-C'}) DETACH DELETE c").consume()


def test_fetch_known_vendor_products_returns_distinct_pairs(driver):
    with driver.session() as s:
        s.run(
            "MERGE (:CPEMatch {match_criteria_id:'mc-1', vendor:'acme', product:'widget'}) "
            "MERGE (:CPEMatch {match_criteria_id:'mc-2', vendor:'acme', product:'widget'}) "
            "MERGE (:CPEMatch {match_criteria_id:'mc-3', vendor:'other', product:'gizmo'})"
        ).consume()
        rows = s.execute_read(lambda tx: fetch_known_vendor_products(tx, limit=2000))
        pairs = {(r["vendor"], r["product"]) for r in rows}
        assert ("acme", "widget") in pairs
        assert ("other", "gizmo") in pairs
        # dedup: acme/widget should appear once despite two CPEMatch rows
        assert len(
            [r for r in rows if r["vendor"] == "acme" and r["product"] == "widget"]
        ) == 1
    with driver.session() as s:
        s.run(
            "MATCH (m:CPEMatch) WHERE m.match_criteria_id IN "
            "['mc-1','mc-2','mc-3'] DETACH DELETE m"
        ).consume()
