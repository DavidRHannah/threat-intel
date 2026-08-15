"""Search endpoint: CONTAINS-based match over CVE/ThreatActor/MalwareFamily.

No full-text index exists in the graph yet (spec decision 6, 2026-08-13 design doc) -- fine
at current volume (~1700 CVEs, low hundreds of actors/malware). Deferred: proper full-text
index if search quality/scale ever demands it.
"""

import json

from src.common.neo4j_driver import get_driver
from src.delivery.knobs import DeliveryKnobs

_SEARCH_QUERY = """
CALL {
  MATCH (n:CVE)
  WHERE NOT coalesce(n.is_revoked, false)
    AND (toLower(n.cve_id) CONTAINS $q OR toLower(n.description) CONTAINS $q)
  RETURN elementId(n) AS id, 'cve' AS _type, n.cve_id AS cve_id, n.description AS description,
         n.severity_score AS severity_score, null AS name, null AS relevance_score
  LIMIT $limit
}
RETURN id, _type, cve_id, description, severity_score, name, relevance_score
UNION
CALL {
  MATCH (n:ThreatActor)
  WHERE NOT coalesce(n.is_revoked, false)
    AND (toLower(n.name) CONTAINS $q OR toLower(coalesce(n.mitre_id, '')) CONTAINS $q)
  RETURN elementId(n) AS id, 'actor' AS _type, null AS cve_id, null AS description,
         null AS severity_score, n.name AS name, n.relevance_score AS relevance_score
  LIMIT $limit
}
RETURN id, _type, cve_id, description, severity_score, name, relevance_score
UNION
CALL {
  MATCH (n:MalwareFamily)
  WHERE NOT coalesce(n.is_revoked, false)
    AND (toLower(n.name) CONTAINS $q OR toLower(coalesce(n.mitre_id, '')) CONTAINS $q)
  RETURN elementId(n) AS id, 'malware' AS _type, null AS cve_id, null AS description,
         null AS severity_score, n.name AS name, n.relevance_score AS relevance_score
  LIMIT $limit
}
RETURN id, _type, cve_id, description, severity_score, name, relevance_score
"""


def fetch_search_results(tx, *, query: str, limit: int) -> list[dict]:
    rows = tx.run(_SEARCH_QUERY, q=query.lower(), limit=limit)
    return [{k: v for k, v in dict(r).items() if v is not None} for r in rows]


def _response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


def handler(event, context) -> dict:
    params = (event or {}).get("queryStringParameters") or {}
    query = params.get("q")
    if not query:
        return _response(400, {"error": "missing required query parameter 'q'"})
    knobs = DeliveryKnobs.from_config()
    driver = get_driver()
    with driver.session() as session:
        results = session.execute_read(
            lambda tx: fetch_search_results(tx, query=query, limit=knobs.search_result_limit)
        )
    return _response(200, {"results": results})
