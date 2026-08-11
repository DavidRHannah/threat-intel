"""Severity scoring for a single CVE (FR-ES-02, FR-ES-03, FR-ES-04, FR-ES-05).

No lock: severity is a PURE recompute of current node fields plus current EXPLOITED_BY
degree, so concurrent writers converge on the same value and last-writer-wins is correct.
Contrast confidence.py's node refinement, which accumulates and therefore must lock.
"""

from neo4j import ManagedTransaction

from src.scoring.formulas import SeverityResult, severity
from src.scoring.knobs import SeverityKnobs

_READ = """
MATCH (c:CVE {cve_id: $cve_id})
OPTIONAL MATCH (c)-[:EXPLOITED_BY]->(x)
WHERE x:ThreatActor OR x:MalwareFamily OR x:Campaign
RETURN c.cvss_score           AS cvss_score,
       c.epss_score           AS epss_score,
       coalesce(c.exploited_in_wild, false) AS exploited_in_wild,
       count(DISTINCT x)      AS exploiter_count
"""

# Every property is written on every run, including the nulls: a CVE that regresses to
# `unknown` (e.g. a withdrawn CVSS) must not keep a stale score from a previous run.
_WRITE = """
MATCH (c:CVE {cve_id: $cve_id})
SET c.severity_score          = $score,
    c.severity_band           = $band,
    c.severity_impact         = $impact,
    c.severity_likelihood     = $likelihood,
    c.severity_adoption       = $adoption,
    c.severity_is_provisional = $is_provisional
"""


def score_cve(
    tx: ManagedTransaction, *, cve_id: str, knobs: SeverityKnobs
) -> SeverityResult | None:
    """Recompute and store one CVE's severity. Returns None if the CVE does not exist.

    Read and write share one transaction so the stored score always corresponds to a
    single consistent view of the node and its edges.
    """
    row = tx.run(_READ, cve_id=cve_id).single()
    if row is None:
        return None

    result = severity(
        cvss_score=row["cvss_score"],
        epss_score=row["epss_score"],
        exploited_in_wild=row["exploited_in_wild"],
        exploiter_count=row["exploiter_count"],
        knobs=knobs,
    )
    tx.run(
        _WRITE,
        cve_id=cve_id,
        score=result.score,
        band=result.band,
        impact=result.impact,
        likelihood=result.likelihood,
        adoption=result.adoption,
        is_provisional=result.is_provisional,
    ).consume()
    return result


# The rescan predicate is `cvss_score IS NOT NULL OR exploited_in_wild`, NOT a
# last_updated watermark: `last_updated` is declared in technical-specification.md §3 but
# never written anywhere in this codebase, so a watermark keyed on it would silently
# never fire. Because severity is a pure recompute, an unconditional rescan is both
# correct and cheap enough -- and it is what makes EPSS's ~200k-row daily refresh need no
# SNS events at all.
_SCAN = """
MATCH (c:CVE)
WHERE (c.cvss_score IS NOT NULL OR coalesce(c.exploited_in_wild, false))
  AND ($cursor IS NULL OR elementId(c) > $cursor)
WITH c ORDER BY elementId(c) LIMIT $batch_size
RETURN elementId(c) AS eid, c.cve_id AS cve_id
"""


def rescan_severity_batch(
    tx: ManagedTransaction, *, cursor: str | None, batch_size: int, knobs: SeverityKnobs
) -> tuple[int, str | None]:
    """Rescore one page of scorable CVEs. Returns (count, next cursor)."""
    rows = list(tx.run(_SCAN, cursor=cursor, batch_size=batch_size))
    if not rows:
        return 0, None
    for row in rows:
        score_cve(tx, cve_id=row["cve_id"], knobs=knobs)
    return len(rows), rows[-1]["eid"]
