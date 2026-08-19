from src.nlp.resolution.cleanup import delete_low_confidence_entities, find_removal_candidates


def _make_provisional(driver, label, merge_key, name, mentions):
    """Create a :Provisional node of `label` with one MENTIONS edge per
    (confidence, has_other_edge) tuple in `mentions`."""
    with driver.session() as s:
        s.run(
            f"MERGE (n:{label}:Provisional {{merge_key: $key}}) "
            "SET n.test_fixture = true, n.name = $name",
            key=merge_key,
            name=name,
        ).consume()
        for i, confidence in enumerate(mentions):
            s.run(
                "MERGE (a:Article {source_guid_key: $article_key}) "
                "SET a.test_fixture = true "
                f"WITH a MATCH (n:{label} {{merge_key: $key}}) "
                "MERGE (a)-[m:MENTIONS]->(n) "
                "SET m.extraction_confidence = $confidence, m.extracted_at = datetime()",
                article_key=f"cleanup-test::{merge_key}-{i}",
                key=merge_key,
                confidence=confidence,
            ).consume()


def test_flags_node_whose_best_mention_is_below_floor(driver):
    _make_provisional(driver, "MalwareFamily", "junk-tool", "JunkTool", [0.3, 0.4])
    candidates = find_removal_candidates(driver, floor=0.5)
    assert "junk-tool" in [c["merge_key"] for c in candidates]


def test_does_not_flag_node_with_a_mention_at_or_above_floor(driver):
    _make_provisional(driver, "ThreatActor", "real-actor", "RealActor", [0.3, 0.85])
    candidates = find_removal_candidates(driver, floor=0.5)
    assert "real-actor" not in [c["merge_key"] for c in candidates]


def test_flags_cve_shaped_merge_key_even_above_floor(driver):
    _make_provisional(driver, "MalwareFamily", "cve-2023-46120", "CVE-2023-46120", [0.99])
    candidates = find_removal_candidates(driver, floor=0.5)
    assert "cve-2023-46120" in [c["merge_key"] for c in candidates]


def test_delete_removes_flagged_node_and_its_mentions_edges(driver):
    _make_provisional(driver, "MalwareFamily", "junk-tool-2", "JunkTool2", [0.2])
    result = delete_low_confidence_entities(driver, floor=0.5)
    assert "junk-tool-2" in result.deleted
    with driver.session() as s:
        remaining = s.run(
            "MATCH (n:MalwareFamily {merge_key: 'junk-tool-2'}) RETURN count(n) AS c"
        ).single()["c"]
    assert remaining == 0


def test_delete_skips_node_with_a_non_mentions_edge(driver):
    _make_provisional(driver, "ThreatActor", "linked-actor", "LinkedActor", [0.1])
    with driver.session() as s:
        s.run(
            "MATCH (n:ThreatActor {merge_key: 'linked-actor'}) "
            "MERGE (c:Campaign {merge_key: 'cleanup-test-campaign'}) "
            "SET c.test_fixture = true "
            "MERGE (n)-[:ATTRIBUTED_TO]->(c)"
        ).consume()
    result = delete_low_confidence_entities(driver, floor=0.5)
    assert "linked-actor" in result.skipped
    assert "linked-actor" not in result.deleted
    with driver.session() as s:
        remaining = s.run(
            "MATCH (n:ThreatActor {merge_key: 'linked-actor'}) RETURN count(n) AS c"
        ).single()["c"]
    assert remaining == 1
