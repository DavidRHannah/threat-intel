"""Credibility-change recompute primitive.

Not tied to a numbered FR-RG: this implements `relationships-graph-layer.md` Part 4's
freshness rule, which is design-doc prose rather than a requirement in `requirements/`.

An assertion edge's `confidence` bakes in the asserting feed's `credibility_score` at
write time (see `assertion_edges.upsert_authoritative_assertion`). `credibility_score`
is an editorial value L1 can revise, so a change there would leave every edge from that
source stale. This module provides the recompute primitive; the *trigger* (detecting a
`credibility_score` change on deploy) is L1's config-sync step and is not owned here.

The recompute also re-applies L4's temporal decay (FR-ES-09) to the inferred component,
expressed inline in Cypher rather than by importing `src.scoring.formulas`, so this L3
primitive keeps zero dependency on L4 and stays usable from L1's config-sync Lambda.
Without it, a credibility edit would write the un-decayed inferred base and silently
revive every decayed edge from that feed until the next daily sweep.
"""

from datetime import datetime, timezone

from neo4j import ManagedTransaction


def recompute_confidence_for_feed(
    tx: ManagedTransaction,
    *,
    feed_source: str,
    new_credibility_score: float,
    decay_halflife_days: float = 180.0,
    now: datetime | None = None,
) -> int:
    """Re-derive confidence for every edge the given feed contributes to.

    Re-derives the authoritative component from EVERY contributing feed's current
    Source.credibility_score, not just the changed one: an edge asserted by both
    mitre-attack (1.0) and otx (0.6) must not be downgraded to 0.6 because otx was
    edited. `feed_sources` holds Source.source_id values (e.g. 'mitre-attack', 'otx' --
    see relationships-graph-layer.md Part 4), so that is the join key, not url or name.

    $new_score is used for the changed feed rather than its stored credibility because
    this runs from L1's config-sync, which may not have written the new value to the
    Source node yet.

    The OTHER feeds are read via OPTIONAL MATCH, never a plain MATCH: a plain MATCH is an
    inner join, so an edge whose co-asserting Source node is absent (removed from config
    while edges still reference it in feed_sources -- config-sync syncs removals too) would
    be dropped from the result and SILENTLY SKIPPED by the recompute it was called for,
    under-reporting `touched`. With OPTIONAL MATCH the changed feed's $new_score always
    applies, and missing Sources simply contribute nothing.
    """
    result = tx.run(
        """
        MATCH ()-[r]->() WHERE $feed_source IN r.feed_sources
        OPTIONAL MATCH (s:Source)
            WHERE s.source_id IN r.feed_sources AND s.source_id <> $feed_source
        WITH r, coalesce(max(s.credibility_score), 0.0) AS others
        WITH r, CASE WHEN $new_score > others THEN $new_score ELSE others END AS authoritative
        // L4 decay (FR-ES-09) re-applied here. Without it this recompute would write the
        // UN-decayed inferred base and silently revive every decayed edge from this feed
        // until the next daily sweep. Mirrors src/scoring/formulas.effective_confidence;
        // expressed in Cypher so this L3 primitive takes no dependency on src.scoring.
        WITH r, authoritative,
             coalesce(r.inferred_confidence, 0.0) AS base,
             CASE WHEN r.last_confirmed IS NULL THEN 0.0
                  ELSE duration.inSeconds(r.last_confirmed, $now).seconds / 86400.0
             END AS days
        WITH r, authoritative,
             base * 0.5 ^ (CASE WHEN days < 0.0 THEN 0.0 ELSE days END / $halflife) AS decayed
        SET r.authoritative_confidence = authoritative,
            r.confidence = CASE WHEN authoritative > decayed THEN authoritative ELSE decayed END
        RETURN count(r) AS touched
        """,
        feed_source=feed_source,
        new_score=new_credibility_score,
        halflife=decay_halflife_days,
        now=now or datetime.now(timezone.utc),
    ).single()
    return result["touched"]
