"""Cluster assignment, identity, and merge for Dedup (Phase 3, Step 3.2 of
`plans/02-nlp.md`, FR-DED-03, FR-DED-04, FR-DED-05, FR-DED-06). See
`entity-extraction-nlp-layer/dedup-design.md` Part 2 for the rationale.

`assign_cluster` is the entry point: for a `ResolvedArticle`, it (1) uses Step
3.1's `find_candidates`/`score` to find above-threshold matches, (2) joins the
best-matching existing cluster or starts a new singleton (FR-DED-03), (3)
stamps `story_cluster_id` on every member and recomputes exactly one
`is_cluster_representative` by earliest `published_at`, source
`credibility_score` tie-break (FR-DED-04), populating `dedup_cluster_size` on
the representative only (FR-DED-05), and (4) when the new article bridges two
*different* existing clusters, merges them under the older cluster's id,
re-stamping every member of both (FR-DED-06).

Concurrency safety (dedup-design.md Part 2, "Simultaneous merges are
serialized via the same node-locking pattern used elsewhere" -- see
`src/common/graph/writer.py`'s `merge_relationship`): a cluster merge can touch
every member of *both* merging clusters, not just the new article and one
existing member. The write transaction below locks a "seed" set (the new
article + its above-threshold matches) via `apoc.lock.nodes`, reads their
*fresh* (post-lock) `story_cluster_id`s, discovers each target cluster's full
membership, and repeats -- locking newly-discovered members and re-checking
membership -- until the touched-node set stops growing. Only once that fixed
point is reached (every member of every affected cluster is held under our
lock) does it re-read state and write; no other `assign_cluster` transaction
touching any of the same nodes can interleave, because it would block trying
to acquire a lock we already hold.
"""

from __future__ import annotations

import uuid

from neo4j import Driver, ManagedTransaction

from src.common.config import get_config
from src.nlp.dedup.similarity import ArticleFingerprint, _parse_timestamp, find_candidates, score
from src.nlp.messages import ResolvedArticle, ResolvedEntity

# Neo4j label -> the natural-key property Resolution (src/nlp/resolution/deterministic.py)
# writes on that entity type's node -- mirrors similarity.py's _ENTITY_LABEL_KEY, reversed.
_LABEL_TO_ENTITY_TYPE: dict[str, str] = {"CVE": "cve", "TTP": "ttp", "IOC": "ioc"}
_LABEL_KEY_PROP: dict[str, str] = {"CVE": "cve_id", "TTP": "technique_id", "IOC": "value_type_key"}


def _load_fingerprint(
    session, article_id: str, resolved_entities: list[ResolvedEntity] | None = None
) -> ArticleFingerprint:
    """Loads the Neo4j-only fields (`cleaned_text`/`content_hash`/`published_at`) for
    `article_id` and assembles an `ArticleFingerprint`. `resolved_entities` is the
    already-known set for the article being clustered (its `ResolvedArticle` carries
    it); when omitted (candidates, which we only have an id for), it's rebuilt from
    the article's `MENTIONS` edges."""
    record = session.run(
        "MATCH (a:Article {source_guid_key: $id}) "
        "RETURN a.cleaned_text AS cleaned_text, a.content_hash AS content_hash, "
        "a.published_at AS published_at",
        id=article_id,
    ).single()

    cleaned_text = (record["cleaned_text"] if record else None) or ""
    content_hash = (record["content_hash"] if record else None) or ""
    published_at = record["published_at"] if record else None

    if resolved_entities is None:
        resolved_entities = []
        rows = session.run(
            "MATCH (:Article {source_guid_key: $id})-[:MENTIONS]->(e) "
            "RETURN labels(e) AS labels, e.cve_id AS cve_id, "
            "e.technique_id AS technique_id, e.value_type_key AS value_type_key",
            id=article_id,
        )
        for row in rows:
            for label in row["labels"]:
                key_prop = _LABEL_KEY_PROP.get(label)
                if key_prop is None:
                    continue
                key_value = row[key_prop]
                if key_value is None:
                    continue
                resolved_entities.append(
                    ResolvedEntity(
                        canonical_node_key=key_value,
                        entity_type=_LABEL_TO_ENTITY_TYPE[label],
                        resolution_status="resolved",
                        node_confidence=1.0,
                    )
                )
                break

    return ArticleFingerprint(
        article_id=article_id,
        published_at=published_at,
        content_hash=content_hash,
        cleaned_text=cleaned_text,
        resolved_entities=resolved_entities,
    )


def _lock_nodes(tx: ManagedTransaction, article_ids: list[str]) -> None:
    """Locks all `Article` nodes in `article_ids` in deterministic (`elementId`)
    order via `apoc.lock.nodes`, reusing the endpoint-locking pattern from
    `src/common/graph/writer.py::merge_relationship`, extended here from 2
    endpoints to an arbitrary set of cluster members. The lock is held for the
    remainder of the enclosing transaction."""
    if not article_ids:
        return
    tx.run(
        "MATCH (a:Article) WHERE a.source_guid_key IN $ids "
        "WITH a ORDER BY elementId(a) "
        "WITH collect(a) AS nodes "
        "CALL apoc.lock.nodes(nodes) "
        "RETURN count(*) AS locked",
        ids=article_ids,
    ).consume()


def _assign_cluster_tx(tx: ManagedTransaction, self_id: str, matched_ids: list[str], new_cluster_id: str) -> str:
    # Fixed-point closure: start from the seed nodes we already know about (self +
    # above-threshold matches), lock them, discover their cluster(s)' full membership,
    # lock any newly-discovered members too, and repeat until nothing new turns up.
    # This guarantees every member of every cluster this write can affect is locked
    # before we take the fresh read that decides the outcome.
    locked_ids: set[str] = set()
    to_lock: set[str] = {self_id, *matched_ids}
    while to_lock:
        _lock_nodes(tx, sorted(to_lock))
        locked_ids |= to_lock

        rows = tx.run(
            "MATCH (a:Article) WHERE a.source_guid_key IN $ids "
            "RETURN a.story_cluster_id AS cluster_id",
            ids=sorted(locked_ids),
        )
        cluster_ids = sorted({r["cluster_id"] for r in rows if r["cluster_id"] is not None})

        if cluster_ids:
            member_rows = tx.run(
                "MATCH (a:Article) WHERE a.story_cluster_id IN $cluster_ids "
                "RETURN a.source_guid_key AS id",
                cluster_ids=cluster_ids,
            )
            all_members = {r["id"] for r in member_rows}
        else:
            all_members = set()

        to_lock = all_members - locked_ids

    # Fresh, lock-protected read of every touched member's current state.
    rows = tx.run(
        "MATCH (a:Article) WHERE a.source_guid_key IN $ids "
        "OPTIONAL MATCH (a)-[:PUBLISHED_BY]->(s:Source) "
        "RETURN a.source_guid_key AS id, a.story_cluster_id AS cluster_id, "
        "a.published_at AS published_at, s.credibility_score AS credibility",
        ids=sorted(locked_ids),
    )
    members = [dict(r) for r in rows]

    existing_cluster_ids = sorted({m["cluster_id"] for m in members if m["cluster_id"] is not None})

    if not existing_cluster_ids:
        final_id = new_cluster_id
    elif len(existing_cluster_ids) == 1:
        final_id = existing_cluster_ids[0]
    else:
        # FR-DED-06: bridging 2+ existing clusters keeps the *older* one's id -- the
        # cluster whose own (pre-bridge) members published earliest.
        def _oldest_member_time(cluster_id: str):
            return min(
                _parse_timestamp(m["published_at"])
                for m in members
                if m["cluster_id"] == cluster_id
            )

        final_id = min(existing_cluster_ids, key=_oldest_member_time)

    # Representative: earliest published_at; ties broken by source credibility_score,
    # highest wins. A member with no PUBLISHED_BY edge (missing credibility_score) is
    # treated as lowest tie-break priority, never preferred over a member with a score.
    def _representative_key(m: dict):
        credibility = m["credibility"]
        credibility_rank = credibility if credibility is not None else float("-inf")
        return (_parse_timestamp(m["published_at"]), -credibility_rank)

    representative = min(members, key=_representative_key)

    tx.run(
        "UNWIND $ids AS aid "
        "MATCH (a:Article {source_guid_key: aid}) "
        "SET a.story_cluster_id = $cluster_id, "
        "a.is_cluster_representative = (aid = $rep_id), "
        "a.dedup_cluster_size = CASE WHEN aid = $rep_id THEN $size ELSE null END",
        ids=[m["id"] for m in members],
        cluster_id=final_id,
        rep_id=representative["id"],
        size=len(members),
    ).consume()

    return final_id


def assign_cluster(driver: Driver, article: ResolvedArticle) -> str:
    """FR-DED-03/04/05/06. Returns the `story_cluster_id` `article` ends up in."""
    window_hours = int(get_config("dedup_window_hours", default="72"))
    threshold = float(get_config("dedup_threshold", default="0.6"))

    candidate_ids = find_candidates(driver, article, window_hours)

    matched_ids: list[str] = []
    if candidate_ids:
        with driver.session() as session:
            self_fp = _load_fingerprint(
                session, article.article_id, resolved_entities=article.resolved_entities
            )
            for candidate_id in candidate_ids:
                candidate_fp = _load_fingerprint(session, candidate_id)
                if score(self_fp, candidate_fp) >= threshold:
                    matched_ids.append(candidate_id)

    new_cluster_id = str(uuid.uuid4())
    with driver.session() as session:
        return session.execute_write(
            _assign_cluster_tx, article.article_id, matched_ids, new_cluster_id
        )
