"""Dedup Lambda handler (Phase 3, Step 3.3 of `plans/02-nlp.md`, FR-DED-07,
FR-DED-08).

Consumes `ResolvedArticle` (Resolution's output shape, see
`src/nlp/resolution/handler.py`) from the `resolved-articles` SQS queue,
delegates cluster assignment to Step 3.2's `assign_cluster`
(`src/nlp/dedup/clustering.py`), and re-emits the *full* `StoryCluster` --
every current member plus the union of resolved entities across all members
-- to the `story-clusters` SQS queue (FR-DED-07).

`assign_cluster` only returns the winning `story_cluster_id`; it does not
return membership or entities. This handler recovers both by querying Neo4j
after the assignment write commits:

- **Membership** is a direct read of `Article.story_cluster_id`, stamped by
  `assign_cluster` itself.
- **Union of resolved entities** requires a design choice: `ResolvedEntity`
  (`resolution_status`/`node_confidence`) is not persisted anywhere as a
  queryable unit today -- Resolution only writes a `MENTIONS` edge carrying
  `extraction_confidence`, not `node_confidence` or `resolution_status`. This
  handler denormalizes: it stores each incoming `ResolvedArticle`'s
  `resolved_entities` as a JSON blob on that article's `Article` node
  (`a.resolved_entities_json`), mirroring this codebase's existing pattern of
  denormalizing per-article state directly onto `Article` (`content_hash`,
  `cleaned_text`, `dedup_cluster_size`). Computing the union then means
  reading every member's stored blob and merging by `canonical_node_key`,
  keeping the highest `node_confidence` per key. This is more robust than
  reconstructing from `MENTIONS` edges (which cannot recover
  `resolution_status`/`node_confidence` at all) and survives cluster
  membership changes from later re-processing.

FR-DED-07's "re-emit whenever membership changes": every `assign_cluster`
call either creates a new singleton, adds the article to an existing cluster,
or bridges two clusters -- membership always changes for at least the
incoming article. There is no no-op case worth special-casing here; this
handler emits a `StoryCluster` after every successful `assign_cluster` call.
"""

from __future__ import annotations

import json
from typing import Any

import boto3

from src.common.config import get_config
from src.common.neo4j_driver import get_driver
from src.nlp.dedup.clustering import assign_cluster
from src.nlp.messages import ResolvedArticle, ResolvedEntity, StoryCluster


def _store_resolved_entities(driver: Any, article: ResolvedArticle) -> None:
    """Denormalizes `article.resolved_entities` onto its `Article` node so the
    union across a cluster can be recovered later (see module docstring)."""
    payload = json.dumps([e.to_dict() for e in article.resolved_entities])

    def _tx(tx):
        tx.run(
            "MATCH (a:Article {source_guid_key: $id}) "
            "SET a.resolved_entities_json = $payload",
            id=article.article_id,
            payload=payload,
        ).consume()

    with driver.session() as session:
        session.execute_write(_tx)


def _build_story_cluster(driver: Any, story_cluster_id: str) -> StoryCluster:
    """Reads back every current member of `story_cluster_id` and the union of
    their stored `resolved_entities_json`, deduped by `canonical_node_key`
    keeping the max `node_confidence` per key."""
    with driver.session() as session:
        rows = session.run(
            "MATCH (a:Article {story_cluster_id: $id}) "
            "RETURN a.source_guid_key AS article_id, "
            "a.resolved_entities_json AS resolved_entities_json",
            id=story_cluster_id,
        )
        members = list(rows)

    article_ids = [m["article_id"] for m in members]

    best_by_key: dict[str, ResolvedEntity] = {}
    for m in members:
        raw = m["resolved_entities_json"]
        if not raw:
            continue
        for entity_dict in json.loads(raw):
            entity = ResolvedEntity.from_dict(entity_dict)
            existing = best_by_key.get(entity.canonical_node_key)
            if existing is None or entity.node_confidence > existing.node_confidence:
                best_by_key[entity.canonical_node_key] = entity

    union_resolved_entities = [best_by_key[k] for k in sorted(best_by_key)]

    return StoryCluster(
        story_cluster_id=story_cluster_id,
        article_ids=article_ids,
        union_resolved_entities=union_resolved_entities,
    )


def _process_article(message: dict[str, Any], sqs_client: Any, driver: Any) -> None:
    article = ResolvedArticle.from_dict(message)

    _store_resolved_entities(driver, article)
    story_cluster_id = assign_cluster(driver, article)
    story_cluster = _build_story_cluster(driver, story_cluster_id)

    queue_url = get_config("story_clusters_queue_url")
    sqs_client.send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps(story_cluster.to_dict()),
    )


def handler(
    event: dict[str, Any], context: Any, *, sqs_client: Any = None, driver: Any = None
) -> dict[str, Any]:
    sqs_client = sqs_client if sqs_client is not None else boto3.client("sqs")
    driver = driver if driver is not None else get_driver()

    processed = 0
    for record in event.get("Records", []):
        message = json.loads(record["body"])
        _process_article(message, sqs_client, driver)
        processed += 1

    return {"processed": processed}
