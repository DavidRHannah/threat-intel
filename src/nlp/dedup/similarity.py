"""Candidate generation + similarity scoring for Dedup (Phase 3, Step 3.1 of
`plans/02-nlp.md`, FR-DED-01, FR-DED-02). See `entity-extraction-nlp-layer/
dedup-design.md` Part 1 for the rationale.

`find_candidates` implements entity-blocking (FR-DED-01): for a `ResolvedArticle`,
pull only the *other* Article ids that share >=1 already-resolved entity (via
the existing `MENTIONS` edges written by Resolution) within a time window --
never an O(n^2) all-pairs scan.

`score` (FR-DED-02) is a pure function combining entity-overlap Jaccard
(primary), lexical SimHash similarity (secondary), and time proximity -- with
an exact `content_hash` match short-circuiting to a definite-duplicate score
of 1.0 *without* invoking any of the sub-scorers. It operates on
`ArticleFingerprint`, not `ResolvedArticle` -- `ResolvedArticle` does not carry
`cleaned_text`/`content_hash` (those live only on the `Article` Neo4j node), so
callers load an `ArticleFingerprint` from Neo4j (e.g. via a driver-backed
loader in Step 3.2's assign()) before calling `score`. Keeping `score` free of
the driver keeps it a pure, infra-free unit-tested function.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime

from neo4j import Driver

from src.nlp.messages import ResolvedArticle, ResolvedEntity

# Maps a ResolvedEntity.entity_type to the Neo4j (label, natural-key property)
# pair used by Resolution (src/nlp/resolution/deterministic.py) when it MERGEs
# the entity node and writes the MENTIONS edge.
_ENTITY_LABEL_KEY: dict[str, tuple[str, str]] = {
    "cve": ("CVE", "cve_id"),
    "ttp": ("TTP", "technique_id"),
    "ioc": ("IOC", "value_type_key"),
}

# Scoring weights: entity overlap is the primary signal, lexical similarity
# secondary corroboration, time proximity a tie-breaking signal (dedup-design.md
# Part 1). Threshold tuning against real data is noted there as deferred.
WEIGHT_ENTITY = 0.5
WEIGHT_LEXICAL = 0.3
WEIGHT_TIME = 0.2

# Time-proximity decay horizon, independent of `find_candidates`' blocking
# window_hours (score() is pure/config-free by design -- see module docstring
# and Step 3.1's brief). Matches dedup_window_hours' own default of 72h.
_TIME_PROXIMITY_HORIZON_HOURS = 72.0

_SIMHASH_BITS = 64
_SHINGLE_SIZE = 3


@dataclass
class ArticleFingerprint:
    """The subset of an Article's Neo4j properties + resolved entities needed
    to score it against another article. Not part of `src/nlp/messages.py`'s
    inter-stage message contract -- this is Dedup's internal scoring input,
    assembled by loading `cleaned_text`/`content_hash` from Neo4j alongside the
    `ResolvedArticle` fields that already flowed in from Resolution."""

    article_id: str
    published_at: str
    content_hash: str
    cleaned_text: str
    resolved_entities: list[ResolvedEntity]


def _parse_timestamp(value: str) -> datetime:
    """Article `published_at` values may be ISO 8601 (produced by this
    codebase, e.g. `fetched_at`) or an RFC 822 string straight from
    `feedparser`'s raw `published` field (see `src/collection/rss/poller.py`).
    Try both rather than assuming one."""
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return parsedate_to_datetime(value)


def find_candidates(driver: Driver, article: ResolvedArticle, window_hours: int) -> list[str]:
    """FR-DED-01: entity-blocking candidate generation. Returns the ids of
    other Articles that share a `MENTIONS` edge to any of `article`'s already
    -resolved entities (rejected entities, which have no node, are skipped),
    published within `window_hours` of `article.published_at`. Never includes
    `article` itself."""
    grouped: dict[tuple[str, str], list[str]] = {}
    for entity in article.resolved_entities:
        if not entity.canonical_node_key:
            continue
        mapping = _ENTITY_LABEL_KEY.get(entity.entity_type)
        if mapping is None:
            continue
        grouped.setdefault(mapping, []).append(entity.canonical_node_key)

    if not grouped:
        return []

    self_published_at = _parse_timestamp(article.published_at)
    window = timedelta(hours=window_hours)

    candidate_ids: set[str] = set()
    with driver.session() as session:
        for (label, key_prop), keys in grouped.items():
            result = session.run(
                f"MATCH (other:Article)-[:MENTIONS]->(e:{label}) "
                f"WHERE e.{key_prop} IN $keys AND other.source_guid_key <> $article_id "
                "RETURN DISTINCT other.source_guid_key AS id, other.published_at AS published_at",
                keys=keys,
                article_id=article.article_id,
            )
            for record in result:
                other_published_at = record["published_at"]
                if other_published_at is None:
                    continue
                if abs(_parse_timestamp(other_published_at) - self_published_at) <= window:
                    candidate_ids.add(record["id"])

    return sorted(candidate_ids)


def _entity_jaccard(
    entities_a: list[ResolvedEntity], entities_b: list[ResolvedEntity]
) -> float:
    keys_a = {e.canonical_node_key for e in entities_a if e.canonical_node_key}
    keys_b = {e.canonical_node_key for e in entities_b if e.canonical_node_key}
    union = keys_a | keys_b
    if not union:
        return 0.0
    return len(keys_a & keys_b) / len(union)


def _simhash(text: str) -> int:
    tokens = text.lower().split()
    shingles = (
        [" ".join(tokens[i : i + _SHINGLE_SIZE]) for i in range(len(tokens) - _SHINGLE_SIZE + 1)]
        if len(tokens) >= _SHINGLE_SIZE
        else tokens
    )
    if not shingles:
        return 0

    weights = [0] * _SIMHASH_BITS
    for shingle in shingles:
        digest = int(hashlib.sha256(shingle.encode()).hexdigest(), 16)
        for bit in range(_SIMHASH_BITS):
            weights[bit] += 1 if (digest >> bit) & 1 else -1

    fingerprint = 0
    for bit in range(_SIMHASH_BITS):
        if weights[bit] > 0:
            fingerprint |= 1 << bit
    return fingerprint


def _lexical_similarity(text_a: str, text_b: str) -> float:
    if not text_a or not text_b:
        return 0.0
    hamming_distance = bin(_simhash(text_a) ^ _simhash(text_b)).count("1")
    return 1.0 - (hamming_distance / _SIMHASH_BITS)


def _time_proximity(
    published_a: str, published_b: str, window_hours: float = _TIME_PROXIMITY_HORIZON_HOURS
) -> float:
    delta_hours = abs(
        (_parse_timestamp(published_a) - _parse_timestamp(published_b)).total_seconds()
    ) / 3600
    return max(0.0, 1.0 - (delta_hours / window_hours))


def score(article_a: ArticleFingerprint, article_b: ArticleFingerprint) -> float:
    """FR-DED-02. An exact `content_hash` match is a fast-path definite
    duplicate: short-circuits to 1.0 without invoking any sub-scorer (both a
    perf optimization and semantically correct -- lexical/entity/time signals
    add nothing once the raw text is byte-identical)."""
    if article_a.content_hash and article_a.content_hash == article_b.content_hash:
        return 1.0

    entity_component = _entity_jaccard(article_a.resolved_entities, article_b.resolved_entities)
    lexical_component = _lexical_similarity(article_a.cleaned_text, article_b.cleaned_text)
    time_component = _time_proximity(article_a.published_at, article_b.published_at)

    return (
        WEIGHT_ENTITY * entity_component
        + WEIGHT_LEXICAL * lexical_component
        + WEIGHT_TIME * time_component
    )
