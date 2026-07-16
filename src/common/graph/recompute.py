"""Credibility-change recompute primitive.

Not tied to a numbered FR-RG: this implements `relationships-graph-layer.md` Part 4's
freshness rule, which is design-doc prose rather than a requirement in `requirements/`.

An assertion edge's `confidence` bakes in the asserting feed's `credibility_score` at
write time (see `assertion_edges.upsert_authoritative_assertion`). `credibility_score`
is an editorial value L1 can revise, so a change there would leave every edge from that
source stale. This module provides the recompute primitive; the *trigger* (detecting a
`credibility_score` change on deploy) is L1's config-sync step and is not owned here.
"""

from neo4j import ManagedTransaction


def recompute_confidence_for_feed(
    tx: ManagedTransaction, *, feed_source: str, new_credibility_score: float
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
        SET r.authoritative_confidence = authoritative,
            r.confidence = CASE
                WHEN authoritative > coalesce(r.inferred_confidence, 0.0)
                    THEN authoritative ELSE coalesce(r.inferred_confidence, 0.0)
            END
        RETURN count(r) AS touched
        """,
        feed_source=feed_source,
        new_score=new_credibility_score,
    ).single()
    return result["touched"]
