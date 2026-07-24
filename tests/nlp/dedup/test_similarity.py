"""Tests for Step 3.1 of `plans/02-nlp.md`: candidate generation (FR-DED-01) and
similarity scoring (FR-DED-02).

`find_candidates` is integration (real Neo4j via Docker Compose, mirroring the
`driver` fixture pattern in `tests/nlp/resolution/test_deterministic.py`).
`score` and its sub-scorers are pure-function unit tests requiring no infra.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.nlp.dedup.similarity import (
    ArticleFingerprint,
    find_candidates,
    score,
)
from src.nlp.messages import ResolvedArticle, ResolvedEntity

SELF_ID = "dedup-test-source::dedup-test-self"


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


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _make_article(
    driver, *, source_guid_key: str, published_at: str, cve_id: str | None
) -> None:
    with driver.session() as s:
        s.run(
            "MERGE (a:Article {source_guid_key: $key}) "
            "SET a.test_fixture = true, a.published_at = $published_at",
            key=source_guid_key,
            published_at=published_at,
        ).consume()
        if cve_id is not None:
            s.run(
                "MERGE (c:CVE {cve_id: $cve_id}) SET c.test_fixture = true "
                "WITH c MATCH (a:Article {source_guid_key: $key}) "
                "MERGE (a)-[:MENTIONS]->(c)",
                cve_id=cve_id,
                key=source_guid_key,
            ).consume()


# FR-DED-01: entity-blocking candidate generation
def test_find_candidates_returns_only_articles_sharing_entity_within_window(driver):
    now = datetime.now(timezone.utc)
    self_article = ResolvedArticle(
        article_id=SELF_ID,
        title="Self",
        published_at=_iso(now),
        source_id="dedup-test-source",
        resolved_entities=[
            ResolvedEntity(
                canonical_node_key="CVE-2099-00010",
                entity_type="cve",
                resolution_status="resolved",
                node_confidence=0.9,
            )
        ],
    )

    # Shares the entity, well within the 72h window -> candidate.
    _make_article(
        driver,
        source_guid_key="dedup-test-source::in-window",
        published_at=_iso(now - timedelta(hours=5)),
        cve_id="CVE-2099-00010",
    )
    # Shares the entity, but far outside the window -> not a candidate.
    _make_article(
        driver,
        source_guid_key="dedup-test-source::out-of-window",
        published_at=_iso(now - timedelta(hours=200)),
        cve_id="CVE-2099-00010",
    )
    # In window, but no shared entity -> not a candidate.
    _make_article(
        driver,
        source_guid_key="dedup-test-source::unrelated",
        published_at=_iso(now - timedelta(hours=1)),
        cve_id="CVE-2099-99999",
    )

    candidates = find_candidates(driver, self_article, window_hours=72)

    assert candidates == ["dedup-test-source::in-window"]


def test_find_candidates_excludes_self(driver):
    now = datetime.now(timezone.utc)
    _make_article(
        driver,
        source_guid_key=SELF_ID,
        published_at=_iso(now),
        cve_id="CVE-2099-00011",
    )
    self_article = ResolvedArticle(
        article_id=SELF_ID,
        title="Self",
        published_at=_iso(now),
        source_id="dedup-test-source",
        resolved_entities=[
            ResolvedEntity(
                canonical_node_key="CVE-2099-00011",
                entity_type="cve",
                resolution_status="resolved",
                node_confidence=0.9,
            )
        ],
    )

    candidates = find_candidates(driver, self_article, window_hours=72)

    assert candidates == []


def test_find_candidates_ignores_rejected_entities_with_no_node(driver):
    now = datetime.now(timezone.utc)
    self_article = ResolvedArticle(
        article_id=SELF_ID,
        title="Self",
        published_at=_iso(now),
        source_id="dedup-test-source",
        resolved_entities=[
            ResolvedEntity(
                canonical_node_key="",
                entity_type="ttp",
                resolution_status="rejected",
                node_confidence=0.0,
            )
        ],
    )

    candidates = find_candidates(driver, self_article, window_hours=72)

    assert candidates == []


# FR-DED-02: content_hash short-circuit
def test_score_is_1_on_exact_content_hash_match():
    now = datetime.now(timezone.utc).isoformat()
    a = ArticleFingerprint(
        article_id="a",
        published_at=now,
        content_hash="deadbeef",
        cleaned_text="Some article text about CVE-2099-00001.",
        resolved_entities=[],
    )
    b = ArticleFingerprint(
        article_id="b",
        published_at=now,
        content_hash="deadbeef",
        cleaned_text="Some article text about CVE-2099-00001.",
        resolved_entities=[],
    )

    assert score(a, b) == 1.0


def test_score_content_hash_match_does_not_invoke_subscorers():
    now = datetime.now(timezone.utc).isoformat()
    a = ArticleFingerprint(
        article_id="a",
        published_at=now,
        content_hash="deadbeef",
        cleaned_text="text a",
        resolved_entities=[],
    )
    b = ArticleFingerprint(
        article_id="b",
        published_at=now,
        content_hash="deadbeef",
        cleaned_text="text b",
        resolved_entities=[],
    )

    with (
        mock.patch("src.nlp.dedup.similarity._entity_jaccard") as m_entity,
        mock.patch("src.nlp.dedup.similarity._lexical_similarity") as m_lexical,
        mock.patch("src.nlp.dedup.similarity._time_proximity") as m_time,
    ):
        result = score(a, b)

    assert result == 1.0
    m_entity.assert_not_called()
    m_lexical.assert_not_called()
    m_time.assert_not_called()


def test_score_combines_subscores_when_hash_differs():
    from src.nlp.dedup import similarity as sim_module

    now = datetime.now(timezone.utc)
    a = ArticleFingerprint(
        article_id="a",
        published_at=now.isoformat(),
        content_hash="hash-a",
        cleaned_text="Attackers exploit CVE-2099-00001 in the wild today",
        resolved_entities=[
            ResolvedEntity("CVE-2099-00001", "cve", "resolved", 0.9),
            ResolvedEntity("CVE-2099-00002", "cve", "resolved", 0.9),
        ],
    )
    b = ArticleFingerprint(
        article_id="b",
        published_at=(now - timedelta(hours=10)).isoformat(),
        content_hash="hash-b",
        cleaned_text="Researchers describe active exploitation of CVE-2099-00001",
        resolved_entities=[
            ResolvedEntity("CVE-2099-00001", "cve", "resolved", 0.9),
        ],
    )

    entity_component = sim_module._entity_jaccard(a.resolved_entities, b.resolved_entities)
    lexical_component = sim_module._lexical_similarity(a.cleaned_text, b.cleaned_text)
    time_component = sim_module._time_proximity(a.published_at, b.published_at)
    expected = (
        sim_module.WEIGHT_ENTITY * entity_component
        + sim_module.WEIGHT_LEXICAL * lexical_component
        + sim_module.WEIGHT_TIME * time_component
    )

    result = score(a, b)

    assert result == pytest.approx(expected)
    assert result < 1.0


def test_score_is_lower_for_dissimilar_unrelated_articles():
    now = datetime.now(timezone.utc)
    a = ArticleFingerprint(
        article_id="a",
        published_at=now.isoformat(),
        content_hash="hash-a",
        cleaned_text="Attackers exploit CVE-2099-00001 in the wild today",
        resolved_entities=[
            ResolvedEntity("CVE-2099-00001", "cve", "resolved", 0.9),
        ],
    )
    b = ArticleFingerprint(
        article_id="b",
        published_at=(now - timedelta(hours=500)).isoformat(),
        content_hash="hash-b",
        cleaned_text="A totally unrelated recipe for chocolate cake",
        resolved_entities=[
            ResolvedEntity("CVE-1999-99999", "cve", "resolved", 0.9),
        ],
    )

    result = score(a, b)

    assert result < 0.3


# Sub-scorer unit tests
def test_entity_jaccard_full_overlap_is_1():
    from src.nlp.dedup.similarity import _entity_jaccard

    entities = [ResolvedEntity("CVE-2099-00001", "cve", "resolved", 0.9)]
    assert _entity_jaccard(entities, entities) == 1.0


def test_entity_jaccard_no_overlap_is_0():
    from src.nlp.dedup.similarity import _entity_jaccard

    a = [ResolvedEntity("CVE-2099-00001", "cve", "resolved", 0.9)]
    b = [ResolvedEntity("CVE-2099-00002", "cve", "resolved", 0.9)]
    assert _entity_jaccard(a, b) == 0.0


def test_entity_jaccard_empty_both_is_0():
    from src.nlp.dedup.similarity import _entity_jaccard

    assert _entity_jaccard([], []) == 0.0


def test_lexical_similarity_identical_text_is_1():
    from src.nlp.dedup.similarity import _lexical_similarity

    text = "The quick brown fox jumps over the lazy dog repeatedly for testing"
    assert _lexical_similarity(text, text) == 1.0


def test_lexical_similarity_very_different_text_is_low():
    from src.nlp.dedup.similarity import _lexical_similarity

    a = "Attackers exploit a critical vulnerability in widely used enterprise software"
    b = "The chef prepared a delicious three course meal for the wedding banquet"
    assert _lexical_similarity(a, b) < 0.6


def test_time_proximity_same_instant_is_1():
    from src.nlp.dedup.similarity import _time_proximity

    now = datetime.now(timezone.utc).isoformat()
    assert _time_proximity(now, now) == 1.0


def test_time_proximity_beyond_window_is_0():
    from src.nlp.dedup.similarity import _time_proximity

    now = datetime.now(timezone.utc)
    later = now + timedelta(hours=1000)
    assert _time_proximity(now.isoformat(), later.isoformat(), window_hours=72) == 0.0
