from datetime import datetime

from src.common.config import get_config
from src.common.graph.writer import _check_identifier, _match_clause, merge_relationship


def validate_edge_direction(rel_type: str, *, end_label: str) -> None:
    if rel_type == "ASSOCIATED_WITH" and end_label != "IOC":
        raise ValueError(
            f"ASSOCIATED_WITH must end at IOC, got end_label={end_label!r} "
            "(FR-RG-10: use INDICATES for IOC-to-CVE)"
        )


def _existing(tx, start_label, start_key, end_label, end_key, rel_type):
    """Read the current edge state under the endpoint lock.

    Locks both endpoints itself rather than relying on merge_relationship's lock:
    Neo4j takes no read locks, so an unlocked read here would let two concurrent
    writers derive their writes from the same stale pre-state and lose one of the
    two noisy-OR contributions. APOC locks are held to end of transaction, so
    merge_relationship's later lock is a re-entrant no-op and the whole
    read-modify-write serializes.

    Validates its own interpolated identifiers: it runs BEFORE merge_relationship,
    so without this the writer's ValueError contract never fires for these callers.
    """
    _check_identifier(rel_type, "rel_type")
    params = {f"a_{k}": v for k, v in start_key.items()}
    params.update({f"b_{k}": v for k, v in end_key.items()})
    row = tx.run(
        f"MATCH {_match_clause('a', start_label, start_key)}, "
        f"      {_match_clause('b', end_label, end_key)} "
        "WITH a, b, CASE WHEN elementId(a) <= elementId(b) THEN [a, b] ELSE [b, a] END AS ordered "
        "CALL apoc.lock.nodes(ordered) "
        "WITH a, b "
        f"OPTIONAL MATCH (a)-[r:{rel_type}]->(b) "
        "RETURN r AS r",
        **params,
    ).single()
    return dict(row["r"]) if row and row["r"] is not None else None


def _cap() -> int:
    return int(get_config("source_article_ids_cap", default="50"))


def upsert_authoritative_assertion(
    tx, *, start_label, start_key, end_label, end_key, rel_type,
    feed_source: str, credibility_score: float, now: datetime,
) -> str:
    validate_edge_direction(rel_type, end_label=end_label)
    existing = _existing(tx, start_label, start_key, end_label, end_key, rel_type)
    origin = set(existing.get("origin", [])) if existing else set()
    origin.add("authoritative")
    feed_sources = set(existing.get("feed_sources", [])) if existing else set()
    feed_sources.add(feed_source)

    # confidence is DERIVED from the two stored components, never ratcheted against the
    # previously stored confidence -- see the Interfaces note and §6. Note we read
    # inferred_confidence but never write it here: an authoritative write must not clobber
    # the inferred component.
    authoritative = max(
        credibility_score,
        existing.get("authoritative_confidence", 0.0) if existing else 0.0,
    )
    inferred = existing.get("inferred_confidence", 0.0) if existing else 0.0

    props = {
        "origin": sorted(origin),
        "feed_sources": sorted(feed_sources),
        "authoritative_confidence": authoritative,
        "confidence": max(authoritative, inferred),
        "last_confirmed": now,
    }
    on_create = {**props, "first_observed": now}
    return merge_relationship(
        tx, start_label=start_label, start_key=start_key,
        end_label=end_label, end_key=end_key, rel_type=rel_type,
        on_create=on_create, on_match=props,
    )


def upsert_inferred_assertion(
    tx, *, start_label, start_key, end_label, end_key, rel_type,
    story_cluster_id: str, contribution: float, source_article_ids: list[str],
    now: datetime,
) -> str:
    validate_edge_direction(rel_type, end_label=end_label)
    existing = _existing(tx, start_label, start_key, end_label, end_key, rel_type)
    contributing = set(existing.get("contributing_story_cluster_ids", [])) if existing else set()
    already_seen = story_cluster_id in contributing

    if already_seen:
        # `existing` cannot be None here: story_cluster_id can only be in `contributing`
        # if the edge already exists. Index directly rather than falling back to a
        # default so a broken invariant fails loudly instead of silently substituting.
        inferred_confidence = existing["inferred_confidence"]
        article_ids = existing.get("source_article_ids", [])
        supporting_count = existing.get("supporting_article_count", len(article_ids))
    else:
        prior = existing.get("inferred_confidence", 0.0) if existing else 0.0
        inferred_confidence = 1 - (1 - prior) * (1 - contribution)
        contributing.add(story_cluster_id)
        existing_ids = existing.get("source_article_ids", []) if existing else []
        new_ids = [a for a in source_article_ids if a not in existing_ids]
        article_ids = (existing_ids + new_ids)[: _cap()]
        supporting_count = (
            existing.get("supporting_article_count", len(existing_ids)) if existing else 0
        ) + len(new_ids)

    origin = set(existing.get("origin", [])) if existing else set()
    origin.add("inferred")
    # Derived from the stored components; the authoritative component is read, never written
    # here. Absent on an inferred-only edge, hence the 0.0 default.
    authoritative = existing.get("authoritative_confidence", 0.0) if existing else 0.0

    props = {
        "origin": sorted(origin),
        "inferred_confidence": inferred_confidence,
        "confidence": max(authoritative, inferred_confidence),
        "source_article_ids": article_ids,
        # Monotonic count of article *contributions*, not of distinct articles: past the
        # cap, new ids are deduped against the capped `source_article_ids` list, so an
        # article outside the stored window would be counted again. Overcounts, never
        # undercounts; exact below the cap. Inherent to the capped design, not a bug —
        # FR-RG-06 and technical-specification.md §3.2 were amended to match (2026-07-16).
        "supporting_article_count": supporting_count,
        # Not capped: this list IS the idempotency check. _cap() bounds source_article_ids
        # (a size/display concern); truncating cluster ids would make an evicted id read as
        # new on re-emission, re-firing the noisy-OR and inflating confidence — exactly the
        # no-op guarantee this field exists to provide. Bounded in practice by real story
        # volume per edge.
        "contributing_story_cluster_ids": sorted(contributing),
        "last_confirmed": now,
    }
    on_create = {**props, "first_observed": now}
    return merge_relationship(
        tx, start_label=start_label, start_key=start_key,
        end_label=end_label, end_key=end_key, rel_type=rel_type,
        on_create=on_create, on_match=props,
    )
