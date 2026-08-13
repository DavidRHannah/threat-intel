"""EPSS daily batch refresh — batch update of epss_score on existing CVE nodes.

This is the one write path in the collection layer that must NOT lazily create
CVE nodes. EPSS enrichment is explicitly enrichment-only (FR-DC-24): it updates
existing CVE nodes and never creates nodes for CVEs in the bulk file with no
graph match. All other write paths in this layer (NVD, CISA KEV, GHSA, OTX,
abuse.ch) lazily create bare CVE stubs on first reference; EPSS is the deliberate
exception, enforced by a bare MATCH+SET (never MERGE).
"""

from collections.abc import Callable
from typing import Any

from neo4j import Driver

from src.common.config import get_config

_EPSS_FILE_URL_DEFAULT = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_DEFAULT_BATCH_SIZE = 500


def refresh_epss_scores(
    driver: Driver, fetch_epss_file_fn: Callable[[], str], batch_size: int | None = None
) -> int:
    """Refresh epss_score on existing CVE nodes from a bulk EPSS CSV file.

    Deliberately uses MATCH+SET (never MERGE) to enforce FR-DC-24's "never create"
    constraint. A MERGE would silently create new CVE nodes for any CSV row with no
    existing graph match — which violates the enrichment-only semantics. Do NOT
    "fix" this to MERGE by pattern-matching on the rest of the layer's lazy-creation
    convention; this method is the explicit exception to that rule.

    Writes are batched via UNWIND (default 500 rows/round-trip, `epss_batch_size`
    config knob) rather than one session.run() per row: confirmed live in production
    (2026-08-13) that one-call-per-row against the real ~200k-row bulk file always
    hits the Lambda's execution timeout before finishing (3/1675 CVEs updated in a
    300s run) -- this isn't a hypothetical perf concern, the daily refresh could not
    complete at all before batching.

    Args:
        driver: Neo4j driver
        fetch_epss_file_fn: callable returning the EPSS CSV content as a string
        batch_size: rows per UNWIND round-trip; defaults to the `epss_batch_size`
            config knob (500) when not given

    Returns:
        Count of CVE nodes whose epss_score was updated
    """
    if batch_size is None:
        batch_size = int(get_config("epss_batch_size", default=str(_DEFAULT_BATCH_SIZE)))

    csv_content = fetch_epss_file_fn()
    lines = csv_content.strip().split("\n")
    if not lines:
        return 0

    # Skip header; parse CSV rows, skipping malformed ones before batching.
    parsed: list[dict[str, Any]] = []
    for row in lines[1:]:
        parts = row.split(",")
        if len(parts) < 2:
            continue
        cve_id = parts[0].strip()
        epss_str = parts[1].strip()
        try:
            epss_score = float(epss_str)
        except ValueError:
            continue  # Skip malformed lines.
        parsed.append({"id": cve_id, "score": epss_score})

    count = 0
    with driver.session() as session:
        for i in range(0, len(parsed), batch_size):
            chunk = parsed[i : i + batch_size]
            # FR-DC-24: MATCH only; never MERGE. This ensures we only update
            # existing CVE nodes and never create new ones for unmatched CSV rows.
            result = session.run(
                "UNWIND $rows AS row "
                "MATCH (c:CVE {cve_id: row.id}) SET c.epss_score = row.score "
                "RETURN count(c) AS updated",
                rows=chunk,
            )
            record = result.single()
            if record:
                count += record["updated"]

    return count


def _default_fetch_epss_file() -> str:
    """Download the current EPSS bulk file and return its (gunzipped) CSV text.

    EPSS publishes a single gzipped CSV of the full current scoring set; this is the
    production seam `refresh_epss_scores` consumes. The two-line CSV preamble (a comment
    line then the header) is left intact -- `refresh_epss_scores` skips the first line and
    tolerates the malformed comment row via its per-row length/parse guards.
    """
    import gzip

    import httpx

    url = get_config("epss_file_url", default=_EPSS_FILE_URL_DEFAULT)
    with httpx.Client(follow_redirects=True) as client:
        response = client.get(url, timeout=60.0)
        response.raise_for_status()
        return gzip.decompress(response.content).decode("utf-8")


def handler(
    event: Any = None,
    context: Any = None,
    *,
    driver: Driver | None = None,
    fetch_epss_file_fn: Callable[[], str] | None = None,
) -> dict:
    """Lambda entry point for the daily EPSS batch refresh (Step Functions task state).

    Enrichment-only (FR-DC-24): updates `epss_score` on existing CVE nodes, never creates
    them. Seams (`driver`, `fetch_epss_file_fn`) are injectable for tests; production
    resolves the shared Neo4j driver and downloads the real EPSS bulk file.
    """
    if driver is None:
        from src.common.neo4j_driver import get_driver

        driver = get_driver()
    if fetch_epss_file_fn is None:
        fetch_epss_file_fn = _default_fetch_epss_file

    updated = refresh_epss_scores(driver, fetch_epss_file_fn)
    return {"cves_updated": updated}
