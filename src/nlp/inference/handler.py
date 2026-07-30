"""Inference Lambda handler (Phase 4, Step 4.4 of `plans/02-nlp.md`,
FR-INF-06, FR-INF-07, FR-INF-08).

Consumes `StoryCluster` messages (Dedup's output shape, see
`src/nlp/dedup/handler.py`) from the `story-clusters` SQS queue. Per cluster:

1. Reads the representative article's `cleaned_text`/`content_hash` directly
   from Neo4j (`Article.is_cluster_representative`) -- this is the RE-target
   text/hash (`entity-extraction-nlp-layer/inference-design.md` Part 3).
2. Filters `union_resolved_entities` down to entities that were actually
   resolved to a real node: a `rejected` mention (FR-RES-07) carries an
   empty `canonical_node_key` and no node was ever created for it, so it is
   dropped here before it can ever reach the LLM or a graph write.
3. Checks the RE-cache (`src/nlp/inference/re_cache.py`, Step 4.3) on that
   hash; a hit skips `extract_relations` entirely (FR-INF-07) and reuses the
   cached `CandidateRelation`s. A miss calls `extract_relations` (Step 4.1)
   and stores the result.
4. Maps each `CandidateRelation` onto the Layer 2 edge catalog via
   `validate_and_map` (Step 4.1); candidates the catalog doesn't sanction
   (or that are `negated`) come back `None` and are dropped. The mapped
   edge's `assertion_strength` (already hedge-discounted by
   `validate_and_map`, not the raw `CandidateRelation` value) is what feeds
   `compute_contribution` (Step 4.2) -- see `confidence.py`'s docstring.
5. Writes each surviving `MappedEdge` via `upsert_inferred_assertion`
   (`src.common.graph.assertion_edges`, `plans/03-graph.md` Task 3) --
   **always inside `session.execute_write(...)`, never a bare `Session`**:
   `upsert_inferred_assertion`'s locked read (`_existing`) and its write
   (`merge_relationship`) must be one atomic transaction, or L3's proven
   lost-update race (9 of 10 concurrent contributions dropped) silently
   returns. This module does not reimplement any of that noisy-OR/
   idempotency math -- it only supplies the endpoint labels/keys and calls in.
6. Publishes a `graph-writes` SNS notification per write via
   `publish_graph_write` (`src.common.graph.publish`), mirroring the pattern
   established in `src/nlp/resolution/handler.py`.

FR-INF-08 (never assert relationships across distinct story clusters) is
structural by construction, not a runtime check: `extract_relations` is only
ever called with one cluster's representative text and its own
`union_resolved_entities`, so a candidate relationship between entities that
only co-occur in *different* clusters can never be proposed in the first
place -- there is no guard clause to write.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import anthropic
import boto3

from src.common.config import get_config
from src.common.graph.assertion_edges import upsert_inferred_assertion
from src.common.graph.publish import publish_graph_write
from src.common.neo4j_driver import get_driver
from src.nlp.inference.confidence import compute_contribution
from src.nlp.inference.re_cache import get_cached_result, put_cached_result
from src.nlp.inference.relation_extraction import extract_relations, validate_and_map
from src.nlp.messages import StoryCluster

# Neo4j node-label -> natural-key property, for turning a MappedEdge's
# start_key/end_key (a bare canonical_node_key string) into the {prop: value}
# dict upsert_inferred_assertion/merge_relationship need. Mirrors
# src/nlp/resolution/handler.py's _DETERMINISTIC_LABEL_BY_TYPE /
# _DETERMINISTIC_KEY_PROP_BY_TYPE, extended with the fuzzy-resolved and
# inference-only labels that can appear at an inferred edge's endpoints
# (ThreatActor/MalwareFamily/Campaign all key on `merge_key` -- see
# src/nlp/resolution/fuzzy.py).
_KEY_PROP_BY_LABEL = {
    "CVE": "cve_id",
    "TTP": "technique_id",
    "IOC": "value_type_key",
    "ThreatActor": "merge_key",
    "MalwareFamily": "merge_key",
    "Campaign": "merge_key",
}


def _entity_key(label: str, canonical_node_key: str) -> dict:
    return {_KEY_PROP_BY_LABEL[label]: canonical_node_key}


def _representative_text_and_hash(driver: Any, story_cluster_id: str) -> tuple[str, str] | None:
    """Reads the RE-target text/hash straight off the representative
    `Article` node (`content_hash` already exists per
    technical-specification.md §3.1 -- used directly rather than re-hashing
    text here). Returns None if no representative is found (e.g. the
    cluster's representative article node was since removed)."""
    with driver.session() as session:
        record = session.run(
            "MATCH (a:Article {story_cluster_id: $id, is_cluster_representative: true}) "
            "RETURN a.cleaned_text AS cleaned_text, a.content_hash AS content_hash",
            id=story_cluster_id,
        ).single()
    if record is None:
        return None
    return (record["cleaned_text"] or "", record["content_hash"] or "")


def _process_story_cluster(
    message: dict[str, Any], driver: Any, re_cache_table: Any, get_llm_client: Any
) -> None:
    story_cluster = StoryCluster.from_dict(message)

    rep = _representative_text_and_hash(driver, story_cluster.story_cluster_id)
    if rep is None:
        return  # nothing to infer from without a representative article
    text, content_hash = rep

    # FR-RES-07: a rejected mention (e.g. an unknown TTP id, an unclassifiable IOC)
    # carries resolution_status="rejected" and an empty canonical_node_key -- no node
    # was ever created for it. Resolution/Dedup forward these unchanged into
    # union_resolved_entities. validate_and_map maps purely on entity_type and never
    # checks the key, so an unfiltered rejected entity that the LLM happens to name
    # would survive to merge_relationship, which MATCHes (never creates) and raises
    # EndpointNotFoundError on the empty key -- uncaught, poisoning the whole SQS
    # batch. Filtered out here, before the entities ever reach the LLM.
    resolvable_entities = [
        e
        for e in story_cluster.union_resolved_entities
        if e.resolution_status != "rejected" and e.canonical_node_key
    ]
    resolvable_keys = {e.canonical_node_key for e in resolvable_entities}

    cached = get_cached_result(re_cache_table, content_hash)
    if cached is not None:
        relations = cached  # FR-INF-07: unchanged RE-target text -> skip the LLM call
    else:
        relations = extract_relations(text, resolvable_entities, get_llm_client())
        put_cached_result(re_cache_table, content_hash, relations)

    # I3 (review round 2): a cache HIT replays CandidateRelations proposed by a
    # PREVIOUS run against that run's resolvable_entities -- not necessarily this
    # cluster's *current* resolvable set (a mention's resolution can change between
    # cache-write and cache-read, e.g. an entity resolvable then, rejected/removed
    # since). Filtering only the entities passed INTO extract_relations (as the
    # cache-miss path already did) leaves the cache-HIT path unguarded: an unresolvable
    # candidate reaches merge_relationship and raises EndpointNotFoundError uncaught,
    # poisoning the whole SQS batch. Applied uniformly to BOTH paths here, against the
    # relations actually about to be written, not just the entities offered to the LLM.
    relations = [
        r
        for r in relations
        if r.entity_a.get("canonical_node_key") in resolvable_keys
        and r.entity_b.get("canonical_node_key") in resolvable_keys
    ]

    for candidate in relations:
        mapped = validate_and_map(candidate)
        if mapped is None:
            continue

        start_key = _entity_key(mapped.start_label, mapped.start_key)
        end_key = _entity_key(mapped.end_label, mapped.end_key)
        contribution = compute_contribution(mapped)

        with driver.session() as session:
            session.execute_write(
                lambda tx, mapped=mapped, start_key=start_key, end_key=end_key,
                contribution=contribution: upsert_inferred_assertion(
                    tx,
                    start_label=mapped.start_label,
                    start_key=start_key,
                    end_label=mapped.end_label,
                    end_key=end_key,
                    rel_type=mapped.edge_type,
                    story_cluster_id=story_cluster.story_cluster_id,
                    contribution=contribution,
                    source_article_ids=story_cluster.article_ids,
                    now=datetime.now(timezone.utc),
                )
            )

        publish_graph_write(
            rel_type=mapped.edge_type,
            start_key=start_key,
            end_key=end_key,
            outcome="inferred",
            origin="inferred",
        )


def handler(
    event: dict[str, Any],
    context: Any,
    *,
    driver: Any = None,
    re_cache_table: Any = None,
    get_llm_client: Any = None,
) -> dict[str, Any]:
    driver = driver if driver is not None else get_driver()

    if re_cache_table is None:
        dynamodb = boto3.resource("dynamodb")
        re_cache_table = dynamodb.Table(get_config("re_cache_table_name"))

    if get_llm_client is None:
        _llm_client_cache: dict[str, Any] = {}

        def get_llm_client() -> Any:
            if "client" not in _llm_client_cache:
                _llm_client_cache["client"] = anthropic.Anthropic(
                    api_key=get_config("anthropic_api_key")
                )
            return _llm_client_cache["client"]

    processed = 0
    for record in event.get("Records", []):
        message = json.loads(record["body"])
        _process_story_cluster(message, driver, re_cache_table, get_llm_client)
        processed += 1

    return {"processed": processed}
