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
                yesterday_start=(today_start - timedelta(days=1)).isoformat(),
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


def test_fetch_stats_articles_today_delta_is_real_not_hardcoded(driver):
    """The KPI row's "vs last period" trend for articles_today must reflect a real
    day-over-day comparison (yesterday's Article count). The other three KPIs have no
    historical snapshot store to diff against, so trend_deltas omits them entirely rather
    than show a fabricated number."""
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = today_start - timedelta(days=1)
    with driver.session() as session:
        session.run(
            "CREATE (:Article {source_guid_key: 't1', fetched_at: $t1, test_fixture: true})"
            "CREATE (:Article {source_guid_key: 't2', fetched_at: $t2, test_fixture: true})"
            "CREATE (:Article {source_guid_key: 'y1', fetched_at: $y1, test_fixture: true})",
            t1=now.isoformat(),
            t2=now.isoformat(),
            y1=(yesterday_start + timedelta(hours=1)).isoformat(),
        )
    with driver.session() as session:
        stats = session.execute_read(
            lambda tx: fetch_stats(
                tx, today_start=today_start.isoformat(),
                week_start=(today_start - timedelta(days=7)).isoformat(),
                yesterday_start=yesterday_start.isoformat(),
            )
        )
    assert stats["articles_today"] >= 2
    assert stats["articles_yesterday"] >= 1
    assert stats["trend_deltas"]["articles_today"] == (
        stats["articles_today"] - stats["articles_yesterday"]
    )
    assert set(stats["trend_deltas"].keys()) == {"articles_today"}


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


def test_fetch_recent_stories_excludes_iocs_and_ttps_and_prioritizes_actor_and_malware(driver):
    """Raw IOC values and TTP ids aren't scannable as a headline tag -- they must never
    appear in a story's entity list. Among the rest, ThreatActor/MalwareFamily are what
    an analyst actually recognizes at a glance, so they must be picked over CVE/Campaign
    when a story mentions more than the 5-entity cap."""
    with driver.session() as session:
        session.run(
            "CREATE (a:Article {source_guid_key: 'a-priority', title: 'Priority Test', "
            "  story_cluster_id: 'sc-priority', is_cluster_representative: true, "
            "  dedup_cluster_size: 1, published_at: datetime('2026-08-01T00:00:00Z'), "
            "  test_fixture: true})"
            "CREATE (ta:ThreatActor {merge_key: 'ta-1', name: 'TA-One', test_fixture: true})"
            "CREATE (mf:MalwareFamily {merge_key: 'mf-1', name: 'MF-One', test_fixture: true})"
            "CREATE (cve:CVE {cve_id: 'CVE-PRIORITY', test_fixture: true})"
            "CREATE (camp:Campaign {merge_key: 'camp-1', name: 'Camp-One', test_fixture: true})"
            "CREATE (ioc:IOC {value: '1.2.3.4', ioc_type: 'ip', test_fixture: true})"
            "CREATE (ttp:TTP {technique_id: 'T1059', name: 'TTP-One', test_fixture: true})"
            "WITH a, ta, mf, cve, camp, ioc, ttp "
            "CREATE (a)-[:MENTIONS {test_fixture: true}]->(ta) "
            "CREATE (a)-[:MENTIONS {test_fixture: true}]->(mf) "
            "CREATE (a)-[:MENTIONS {test_fixture: true}]->(cve) "
            "CREATE (a)-[:MENTIONS {test_fixture: true}]->(camp) "
            "CREATE (a)-[:MENTIONS {test_fixture: true}]->(ioc) "
            "CREATE (a)-[:MENTIONS {test_fixture: true}]->(ttp)"
        )
    with driver.session() as session:
        rows = session.execute_read(lambda tx: fetch_recent_stories(tx, limit=10))
    story = next(r for r in rows if r["headline"] == "Priority Test")
    types = [e["type"] for e in story["entities"]]
    assert "ioc" not in types
    assert "ttp" not in types
    assert types.index("actor") < types.index("cve")
    assert types.index("malware") < types.index("cve")
    assert types.index("cve") < types.index("campaign")


def test_fetch_recent_stories_balances_across_sources(driver):
    """A high-volume automated source (GHSA in production) must not be able to crowd a
    low-volume curated source (BleepingComputer/Krebs) out of the feed entirely just by
    publishing more often. Round-robin across sources guarantees each source that has
    ANY recent story gets a slot, even if a plain recency sort would exclude it."""
    with driver.session() as session:
        for i in range(8):
            session.run(
                "CREATE (:Article {source_guid_key: $key, source_id: 'many-source', "
                "  title: $title, story_cluster_id: $key, "
                "  is_cluster_representative: true, dedup_cluster_size: 1, "
                "  published_at: $pub, test_fixture: true})",
                key=f"many-{i}", title=f"Many {i}",
                pub=f"2026-08-18T{10 + i:02d}:00:00Z",
            )
        session.run(
            "CREATE (:Article {source_guid_key: 'few-a', source_id: 'few-source-a', "
            "  title: 'Few A', story_cluster_id: 'few-a', "
            "  is_cluster_representative: true, dedup_cluster_size: 1, "
            "  published_at: '2026-08-17T09:00:00Z', test_fixture: true})"
            "CREATE (:Article {source_guid_key: 'few-b', source_id: 'few-source-b', "
            "  title: 'Few B', story_cluster_id: 'few-b', "
            "  is_cluster_representative: true, dedup_cluster_size: 1, "
            "  published_at: '2026-08-17T08:00:00Z', test_fixture: true})"
        )
    with driver.session() as session:
        rows = session.execute_read(lambda tx: fetch_recent_stories(tx, limit=4))
    headlines = {r["headline"] for r in rows}
    assert "Few A" in headlines
    assert "Few B" in headlines
    assert sum(1 for r in rows if r["headline"].startswith("Many")) < 4


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


def test_fetch_subgraph_types_source_neighbours(driver):
    """Source is Article's PUBLISHED_BY neighbour but had no type mapping."""
    with driver.session() as session:
        session.run(
            "CREATE (a:Article {source_guid_key: 'egosrc-1', title: 'Ego Source Test', "
            "  test_fixture: true})"
            "CREATE (s:Source {source_id: 'egosrc-src', test_fixture: true})"
            "WITH a, s "
            "CREATE (a)-[:PUBLISHED_BY {test_fixture: true}]->(s)"
        )
        element_id = session.run(
            "MATCH (a:Article {source_guid_key: 'egosrc-1'}) RETURN elementId(a) AS id"
        ).single()["id"]

    with driver.session() as session:
        result = session.execute_read(lambda tx: fetch_subgraph(tx, element_id=element_id))

    assert result["neighbors"][0]["type"] == "source"


def test_fetch_subgraph_excludes_cpematch_neighbors(driver):
    """CPEMatch is a per-CVE version-range join key, not a browsable intel entity -- a
    single CVE can carry a dozen+ of them (Asset Inventory backfill, 2026-08), which
    overwhelms the ego-graph view with nodes the user never asked to see. They must not
    be returned as subgraph neighbors at all."""
    with driver.session() as session:
        session.run(
            "CREATE (c:CVE {cve_id: 'CVE-EGOCPE', test_fixture: true})"
            "CREATE (m:CPEMatch {match_criteria_id: 'egocpe-1', vendor: 'acme', "
            "  product: 'widget', test_fixture: true})"
            "CREATE (w:CWE {cwe_id: 'CWE-79', test_fixture: true})"
            "WITH c, m, w "
            "CREATE (c)-[:MATCHES {test_fixture: true}]->(m) "
            "CREATE (c)-[:CATEGORIZED_AS {test_fixture: true}]->(w)"
        )
        element_id = session.run(
            "MATCH (c:CVE {cve_id: 'CVE-EGOCPE'}) RETURN elementId(c) AS id"
        ).single()["id"]

    with driver.session() as session:
        result = session.execute_read(lambda tx: fetch_subgraph(tx, element_id=element_id))

    neighbor_types = {n["type"] for n in result["neighbors"]}
    assert "cwe" in neighbor_types
    assert None not in neighbor_types  # CPEMatch would surface as an unmapped/null type
    assert len(result["neighbors"]) == 1
    edge_types = {e["type"] for e in result["edges"]}
    assert "MATCHES" not in edge_types
    assert "CATEGORIZED_AS" in edge_types


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
    assert entity_subgraph_type(["Source"]) == "source"


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


def test_known_vendor_products_prefix_finds_what_an_unscoped_limit_truncates_away(driver):
    """Final-review finding #6. `DISTINCT`+`ORDER BY` are evaluated over the WHOLE label
    before `LIMIT`, so an unscoped autocomplete returns only the alphabetically-first
    `limit` pairs. At production scale that silently drops late-alphabet vendors --
    including `microsoft`, the largest vendor in the live graph -- which is exactly the
    "typo matches nothing, no error" failure the endpoint exists to prevent.

    Seeds more distinct pairs than the limit, all sorting BEFORE the target, and proves
    (a) the unscoped query misses the target and (b) `q` finds it.
    """
    limit = 20
    try:
        with driver.session() as s:
            # 30 pairs sorting before "zvendor" -- more than `limit`.
            s.run(
                "UNWIND range(0, 29) AS i "
                "MERGE (m:CPEMatch {match_criteria_id: 'mc-trunc-' + toString(i)}) "
                "SET m.vendor = 'avendor' + toString(i), m.product = 'p'"
            ).consume()
            s.run(
                "MERGE (m:CPEMatch {match_criteria_id:'mc-trunc-target'}) "
                "SET m.vendor = 'zvendor', m.product = 'zproduct'"
            ).consume()

            unscoped = s.execute_read(
                lambda tx: fetch_known_vendor_products(tx, limit=limit)
            )
            assert not any(r["vendor"] == "zvendor" for r in unscoped), (
                "fixture is not exercising the truncation this test is about"
            )

            scoped = s.execute_read(
                lambda tx: fetch_known_vendor_products(tx, q="zvend", limit=limit)
            )
            assert any(r["vendor"] == "zvendor" for r in scoped)

            # Prefix matches on the PRODUCT half too (the user may type either field).
            by_product = s.execute_read(
                lambda tx: fetch_known_vendor_products(tx, q="zprod", limit=limit)
            )
            assert any(r["product"] == "zproduct" for r in by_product)

            # Case-insensitive from the caller's side: stored values are folded at write
            # time, so the query has to fold the argument.
            upper = s.execute_read(
                lambda tx: fetch_known_vendor_products(tx, q="ZVEND", limit=limit)
            )
            assert any(r["vendor"] == "zvendor" for r in upper)
    finally:
        with driver.session() as s:
            s.run(
                "MATCH (m:CPEMatch) WHERE m.match_criteria_id STARTS WITH 'mc-trunc-' "
                "DETACH DELETE m"
            ).consume()
