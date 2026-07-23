from src.nlp.messages import RawMention, ResolvedArticle, ResolvedEntity, StoryCluster


def test_raw_mention_round_trips_through_dict():
    m = RawMention(
        article_id="a1", entity_type="cve", surface_text="CVE-2026-1234",
        char_span=(10, 24), extraction_confidence=0.95, context_snippet="...",
    )
    assert RawMention.from_dict(m.to_dict()) == m


def test_resolved_article_round_trips_with_nested_entities():
    ra = ResolvedArticle(
        article_id="a1", title="t", published_at="2026-01-01T00:00:00Z", source_id="s1",
        resolved_entities=[
            ResolvedEntity(canonical_node_key="CVE-2026-1234", entity_type="cve",
                            resolution_status="matched_canonical", node_confidence=1.0)
        ],
    )
    assert ResolvedArticle.from_dict(ra.to_dict()) == ra


def test_story_cluster_round_trips():
    sc = StoryCluster(story_cluster_id="c1", article_ids=["a1", "a2"], union_resolved_entities=[])
    assert StoryCluster.from_dict(sc.to_dict()) == sc
