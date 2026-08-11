"""The assertion-edge allowlist (technical-specification.md §3.2).

An ALLOWLIST, never a denylist. Relevance centrality counts assertion edges only; a
denylist would silently start counting any edge type a future layer adds, and
CATEGORIZED_AS (CVE->CWE, structural) would hand every enriched CVE free centrality for
merely having a CWE. Adding an edge type to the schema must be a deliberate decision to
include it here.

Excluded on purpose: MENTIONS, PUBLISHED_BY (evidence), CATEGORIZED_AS (structural).
"""

ASSERTION_EDGE_TYPES: tuple[str, ...] = (
    "EXPLOITED_BY",
    "USES",
    "HAS_SAMPLE",
    "COMMUNICATES_WITH",
    "ASSOCIATED_WITH",
    "INDICATES",
    "ATTRIBUTED_TO",
)
