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


def upsert_authoritative_assertions_bulk(
    tx, *, start_label: str, start_key_prop: str, end_label: str, end_key_prop: str,
    rel_type: str, rows: list[dict], feed_source: str, credibility_score: float, now: datetime,
) -> dict:
    """Batched equivalent of `upsert_authoritative_assertion` for many edges that share
    one (start_label, end_label, rel_type, feed_source, credibility_score) -- one UNWIND
    round trip instead of one `execute_write` per edge.

    Regression fix: the MITRE ATT&CK sync called `upsert_authoritative_assertion` once
    per relationship (~25k for enterprise-attack alone) against remote AuraDB and never
    finished inside the Lambda timeout -- confirmed live across three consecutive 600s
    runs with zero new edges written (see CLAUDE.md Current State). This is the same
    one-round-trip-per-row shape as the EPSS bug fixed in `refresh_epss_scores`.

    `start_label`/`end_label` fix the node schema for every row in the batch, so unlike
    `upsert_authoritative_assertion` this takes each key as a single scalar
    (`start_key_prop`/`end_key_prop` name the property once) rather than a per-row key
    dict -- every current caller (TTP.technique_id, ThreatActor/MalwareFamily/
    Campaign.merge_key) already uses a single-property natural key, so this isn't a
    narrowing of what's actually supported.

    Avoids the two-round-trip read-then-write shape `upsert_authoritative_assertion`
    uses (a separate `_existing` read, needed because that function computes the new
    origin/feed_sources/confidence values in Python from a stale read): here the same
    math is expressed as Cypher CASE expressions evaluated against the relationship's
    live value inside the ONE write statement, so there is no separate read round trip
    to go stale between. `apoc.lock.nodes` is still taken per row (re-entrant with the
    MERGE's own lock) purely for defense in depth / consistency with the rest of this
    module -- not because a second round trip exists here to race against.
    """
    validate_edge_direction(rel_type, end_label=end_label)
    _check_identifier(start_label, "start_label")
    _check_identifier(start_key_prop, "start key property")
    _check_identifier(end_label, "end_label")
    _check_identifier(end_key_prop, "end key property")
    _check_identifier(rel_type, "rel_type")

    if not rows:
        return {"processed": 0, "created": 0}

    query = f"""
    UNWIND $rows AS row
    MATCH (a:{start_label} {{{start_key_prop}: row.start_key}}),
          (b:{end_label} {{{end_key_prop}: row.end_key}})
    WITH a, b, CASE WHEN elementId(a) <= elementId(b) THEN [a, b] ELSE [b, a] END AS ordered
    CALL apoc.lock.nodes(ordered)
    WITH a, b
    MERGE (a)-[r:{rel_type}]->(b)
    ON CREATE SET r.first_observed = $now
    WITH r
    SET r.last_confirmed = $now,
        r.authoritative_confidence = CASE
            WHEN $credibility_score > coalesce(r.authoritative_confidence, 0.0)
            THEN $credibility_score ELSE r.authoritative_confidence END,
        r.origin = CASE
            WHEN NOT 'authoritative' IN coalesce(r.origin, [])
            THEN coalesce(r.origin, []) + 'authoritative' ELSE r.origin END,
        r.feed_sources = CASE
            WHEN NOT $feed_source IN coalesce(r.feed_sources, [])
            THEN coalesce(r.feed_sources, []) + $feed_source ELSE r.feed_sources END
    WITH r
    SET r.confidence = CASE
        WHEN r.authoritative_confidence > coalesce(r.inferred_confidence, 0.0)
        THEN r.authoritative_confidence ELSE r.inferred_confidence END
    RETURN count(r) AS processed
    """
    result = tx.run(
        query, rows=rows, now=now,
        credibility_score=credibility_score, feed_source=feed_source,
    )
    record = result.single()
    summary = result.consume()
    return {
        "processed": record["processed"] if record else 0,
        "created": summary.counters.relationships_created,
    }


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
    outcome = merge_relationship(
        tx, start_label=start_label, start_key=start_key,
        end_label=end_label, end_key=end_key, rel_type=rel_type,
        on_create=on_create, on_match=props,
    )
    # THREE states, not merge_relationship's two. The discriminator between the two
    # non-create states is `already_seen` -- whether this story cluster had ALREADY
    # contributed -- not whether a relationship row was written:
    #   created -- the edge is new.
    #   updated -- the edge existed and a NEW cluster moved the noisy-OR. Genuine new
    #              evidence; merge_relationship reports this only as "matched".
    #   matched -- `already_seen`: a re-emission of a cluster already folded in. A true
    #              no-op, and the ONLY value L4 treats as "nothing newsworthy happened"
    #              (src/scoring/event_handler.py). Collapsing `updated` into `matched`
    #              would silently suppress the novelty spike for real new evidence.
    if outcome == "created":
        return "created"
    return "matched" if already_seen else "updated"
