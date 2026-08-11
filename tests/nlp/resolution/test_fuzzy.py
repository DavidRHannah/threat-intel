from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.nlp.messages import RawMention
from src.nlp.resolution.fuzzy import _create_provisional, build_alias_index, resolve_fuzzy

ARTICLE_ID = "resolution-test-source::resolution-test-guid"


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


@pytest.fixture
def article(driver):
    with driver.session() as s:
        s.run(
            "MERGE (a:Article {source_guid_key: $key}) "
            "SET a.test_fixture = true, a.source_id = 'resolution-test-source', "
            "a.guid = 'resolution-test-guid'",
            key=ARTICLE_ID,
        ).consume()
    return driver


@pytest.fixture
def fancy_bear(article):
    with article.session() as s:
        s.run(
            "MERGE (t:ThreatActor {merge_key: 'G0007'}) "
            "SET t.test_fixture = true, t.mitre_id = 'G0007', "
            "t.name = 'APT28', t.aliases = ['Fancy Bear', 'APT28']"
        ).consume()
    return article


def _mention(surface_text: str, confidence: float = 0.8) -> RawMention:
    return RawMention(
        article_id=ARTICLE_ID,
        entity_type="threat_actor",
        surface_text=surface_text,
        char_span=(0, len(surface_text)),
        extraction_confidence=confidence,
        context_snippet=f"...{surface_text}...",
    )


def _mock_client(matched_merge_key):
    client = MagicMock()
    block = MagicMock(type="tool_use", input={"matched_merge_key": matched_merge_key})
    response = MagicMock()
    response.content = [block]
    client.messages.create.return_value = response
    return client


def test_build_alias_index_maps_normalized_names_and_aliases_to_merge_key(fancy_bear):
    index = build_alias_index(fancy_bear)
    assert index["fancy bear"] == "G0007"
    assert index["apt28"] == "G0007"


# FR-RES-05: "Fancy Bear" resolves at tier 1 (exact-normalized alias index),
# without ever invoking the mocked LLM client.
def test_resolve_fuzzy_exact_tier_never_calls_llm(fancy_bear):
    mention = _mention("Fancy Bear")
    client = _mock_client(matched_merge_key=None)

    result = resolve_fuzzy(fancy_bear, mention, client)

    assert result.canonical_node_key == "G0007"
    assert result.resolution_status == "resolved"
    client.messages.create.assert_not_called()

    with fancy_bear.session() as s:
        count = s.run(
            "MATCH (:Article {source_guid_key: $key})-[r:MENTIONS]->"
            "(:ThreatActor {merge_key: 'G0007'}) RETURN count(r) AS c",
            key=ARTICLE_ID,
        ).single()["c"]
    assert count == 1


# Tier 2 (edit-distance fuzzy) resolves a near-miss typo of a known alias
# without escalating to the LLM tier.
def test_resolve_fuzzy_edit_distance_tier_matches_typo_without_llm(fancy_bear):
    mention = _mention("Fancy Baer")  # transposed letters
    client = _mock_client(matched_merge_key=None)

    result = resolve_fuzzy(fancy_bear, mention, client)

    assert result.canonical_node_key == "G0007"
    client.messages.create.assert_not_called()


# FR-RES-06: a wholly novel actor name with no alias-index hit and a mocked
# tier-3 "none" response creates a :Provisional node.
def test_resolve_fuzzy_novel_name_with_llm_none_creates_provisional(article):
    mention = _mention("Wholly Novel Threat Group Zeta", confidence=0.77)
    client = _mock_client(matched_merge_key=None)

    result = resolve_fuzzy(article, mention, client)
    with article.session() as s:
        s.run(
            "MATCH (n:ThreatActor:Provisional {merge_key: $key}) SET n.test_fixture = true",
            key=result.canonical_node_key,
        ).consume()

    client.messages.create.assert_called_once()
    assert result.canonical_node_key == "wholly novel threat group zeta"

    with article.session() as s:
        node = s.run(
            "MATCH (n:ThreatActor:Provisional {merge_key: $key}) "
            "RETURN n.mitre_id AS mitre_id, n.confidence AS confidence, labels(n) AS labels",
            key=result.canonical_node_key,
        ).single()
    assert node is not None
    assert node["mitre_id"] is None
    assert node["confidence"] == pytest.approx(0.77)
    assert "Provisional" in node["labels"]
    assert "ThreatActor" in node["labels"]

    with article.session() as s:
        edge_count = s.run(
            "MATCH (:Article {source_guid_key: $key})-[r:MENTIONS]->"
            "(:ThreatActor:Provisional {merge_key: $mkey}) RETURN count(r) AS c",
            key=ARTICLE_ID,
            mkey=result.canonical_node_key,
        ).single()["c"]
    assert edge_count == 1


# `first_seen` is stamped ON CREATE only (docstring in `_create_provisional`):
# a re-mention of an already-provisional entity must not reset the staleness
# clock, or FR-ES-10's node-prune predicate goes inert for exactly the
# noisiest, most-mentioned entities. Calling `_create_provisional` twice for
# the SAME merge_key -- the exact MERGE...ON CREATE SET Cypher the review
# fault-injected (widening it to a trailing blanket SET left 278 tests
# green) -- must leave `first_seen` pinned to the FIRST call's timestamp.
def test_create_provisional_stamps_first_seen_on_create_only_not_on_rematch(article, monkeypatch):
    first_ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    second_ts = datetime(2026, 6, 1, tzinfo=timezone.utc)
    clock = iter([first_ts, first_ts, second_ts, second_ts])
    monkeypatch.setattr("src.nlp.resolution.fuzzy._now", lambda: next(clock))

    mention = _mention("Recurring Provisional Group")
    normalized = "recurring provisional group"

    merge_key_1 = _create_provisional(article, mention, "ThreatActor", normalized)
    merge_key_2 = _create_provisional(article, mention, "ThreatActor", normalized)
    assert merge_key_1 == merge_key_2 == normalized

    with article.session() as s:
        s.run(
            "MATCH (n:ThreatActor:Provisional {merge_key: $key}) SET n.test_fixture = true",
            key=normalized,
        ).consume()
        stamped = s.run(
            "MATCH (n:ThreatActor:Provisional {merge_key: $key}) RETURN n.first_seen AS fs",
            key=normalized,
        ).single()["fs"]

    assert stamped.to_native() == first_ts


def test_resolve_fuzzy_confidence_capped_at_point_nine_nine_for_provisional(article):
    mention = _mention("Another Totally Novel Group", confidence=0.999)
    client = _mock_client(matched_merge_key=None)

    result = resolve_fuzzy(article, mention, client)
    with article.session() as s:
        s.run(
            "MATCH (n:ThreatActor:Provisional {merge_key: $key}) SET n.test_fixture = true",
            key=result.canonical_node_key,
        ).consume()

    assert result.node_confidence <= 0.99
