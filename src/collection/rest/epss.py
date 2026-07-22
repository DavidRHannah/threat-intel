"""EPSS daily batch refresh — batch update of epss_score on existing CVE nodes.

This is the one write path in the collection layer that must NOT lazily create
CVE nodes. EPSS enrichment is explicitly enrichment-only (FR-DC-24): it updates
existing CVE nodes and never creates nodes for CVEs in the bulk file with no
graph match. All other write paths in this layer (NVD, CISA KEV, GHSA, OTX,
abuse.ch) lazily create bare CVE stubs on first reference; EPSS is the deliberate
exception, enforced by a bare MATCH+SET (never MERGE).
"""

from collections.abc import Callable

from neo4j import Driver


def refresh_epss_scores(driver: Driver, fetch_epss_file_fn: Callable[[], str]) -> int:
    """Refresh epss_score on existing CVE nodes from a bulk EPSS CSV file.

    Deliberately uses MATCH+SET (never MERGE) to enforce FR-DC-24's "never create"
    constraint. A MERGE would silently create new CVE nodes for any CSV row with no
    existing graph match — which violates the enrichment-only semantics. Do NOT
    "fix" this to MERGE by pattern-matching on the rest of the layer's lazy-creation
    convention; this method is the explicit exception to that rule.

    Args:
        driver: Neo4j driver
        fetch_epss_file_fn: callable returning the EPSS CSV content as a string

    Returns:
        Count of CVE nodes whose epss_score was updated
    """
    csv_content = fetch_epss_file_fn()
    lines = csv_content.strip().split("\n")
    if not lines:
        return 0

    # Skip header; parse CSV rows.
    rows = lines[1:]
    count = 0

    with driver.session() as session:
        for row in rows:
            parts = row.split(",")
            if len(parts) < 2:
                continue
            cve_id = parts[0].strip()
            epss_str = parts[1].strip()

            try:
                epss_score = float(epss_str)
            except ValueError:
                # Skip malformed lines.
                continue

            # FR-DC-24: MATCH only; never MERGE. This ensures we only update
            # existing CVE nodes and never create new ones for unmatched CSV rows.
            result = session.run(
                "MATCH (c:CVE {cve_id: $id}) SET c.epss_score = $score "
                "RETURN count(c) AS updated",
                id=cve_id,
                score=epss_score,
            )
            record = result.single()
            if record:
                count += record["updated"]

    return count
