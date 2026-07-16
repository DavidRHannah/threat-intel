from datetime import datetime

from src.common.config import get_config
from src.common.graph.writer import merge_relationship


def _existing(tx, start_label, start_key, end_label, end_key, rel_type):
    match_a = ", ".join(f"{k}: $a_{k}" for k in start_key)
    match_b = ", ".join(f"{k}: $b_{k}" for k in end_key)
    params = {f"a_{k}": v for k, v in start_key.items()}
    params.update({f"b_{k}": v for k, v in end_key.items()})
    row = tx.run(
        f"MATCH (a:{start_label} {{{match_a}}})-[r:{rel_type}]->(b:{end_label} {{{match_b}}}) "
        "RETURN r AS r",
        **params,
    ).single()
    return dict(row["r"]) if row else None


def _cap() -> int:
    return int(get_config("source_article_ids_cap", default="50"))


def upsert_authoritative_assertion(
    tx, *, start_label, start_key, end_label, end_key, rel_type,
    feed_source: str, credibility_score: float, now: datetime,
) -> str:
    existing = _existing(tx, start_label, start_key, end_label, end_key, rel_type)
    origin = set(existing.get("origin", [])) if existing else set()
    origin.add("authoritative")
    feed_sources = set(existing.get("feed_sources", [])) if existing else set()
    feed_sources.add(feed_source)
    confidence = max(credibility_score, existing.get("confidence", 0.0) if existing else 0.0)

    props = {
        "origin": sorted(origin),
        "feed_sources": sorted(feed_sources),
        "confidence": confidence,
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
    existing = _existing(tx, start_label, start_key, end_label, end_key, rel_type)
    contributing = set(existing.get("contributing_story_cluster_ids", [])) if existing else set()
    already_seen = story_cluster_id in contributing

    if already_seen:
        inferred_confidence = existing.get("inferred_confidence", contribution)
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
    confidence = max(inferred_confidence, existing.get("confidence", 0.0) if existing else 0.0)

    props = {
        "origin": sorted(origin),
        "inferred_confidence": inferred_confidence,
        "confidence": confidence,
        "source_article_ids": article_ids,
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
