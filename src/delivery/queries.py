"""Read-only Cypher queries over the scored graph for the L7 dashboard (FR-DEL-01, FR-DEL-09).

Every function here runs inside `session.execute_read` -- no MERGE/CREATE/SET anywhere in
this module. Field names in returned dicts match frontend/src/api/mockData.js's mock shapes
so the frontend needs no change beyond swapping the mock import for the real hook.
"""

from src.nlp.dedup.similarity import chronological_sort_key

_SHORT_TYPE_BY_LABEL = {
    "CVE": "cve", "ThreatActor": "actor", "MalwareFamily": "malware",
    "TTP": "ttp", "Campaign": "campaign", "IOC": "ioc", "Article": "article",
}

_SUBGRAPH_TYPE_BY_LABEL = {
    "CVE": "cve", "ThreatActor": "threat_actor", "MalwareFamily": "malware_family",
    "TTP": "ttp", "Campaign": "campaign", "IOC": "ioc", "Article": "article",
    "CWE": "cwe",
}

_ID_PROP_BY_LABEL = {
    "CVE": "cve_id", "ThreatActor": "merge_key", "MalwareFamily": "merge_key",
    "TTP": "technique_id", "Campaign": "merge_key",
}


def _label_lookup(labels: list[str], table: dict[str, str]) -> str | None:
    for label in labels:
        if label in table:
            return table[label]
    return None


def entity_short_type(labels: list[str]) -> str | None:
    return _label_lookup(labels, _SHORT_TYPE_BY_LABEL)


def entity_subgraph_type(labels: list[str]) -> str | None:
    return _label_lookup(labels, _SUBGRAPH_TYPE_BY_LABEL)


def _entity_display_id(labels: list[str], props: dict) -> str | None:
    id_prop = _label_lookup(labels, _ID_PROP_BY_LABEL)
    return props.get(id_prop) if id_prop else props.get("name")


_STATS_QUERY = """
CALL { MATCH (c:CVE) RETURN count(c) AS total_cves }
CALL { MATCH (c:CVE) WHERE c.severity_band = 'critical' RETURN count(c) AS critical_cves }
CALL { MATCH (c:CVE) WHERE c.severity_band = 'high' RETURN count(c) AS high_cves }
CALL { MATCH (c:CVE) WHERE c.severity_band = 'medium' RETURN count(c) AS medium_cves }
CALL { MATCH (c:CVE) WHERE c.severity_band = 'low' RETURN count(c) AS low_cves }
CALL { MATCH (c:CVE) WHERE c.severity_band IS NULL RETURN count(c) AS unknown_cves }
CALL { MATCH (c:CVE) WHERE c.exploited_in_wild = true RETURN count(c) AS active_exploits }
CALL {
  MATCH (a:ThreatActor) WHERE NOT coalesce(a.is_revoked, false) RETURN count(a) AS total_actors
}
CALL {
  MATCH (m:MalwareFamily) WHERE NOT coalesce(m.is_revoked, false)
  RETURN count(m) AS total_malware
}
CALL { MATCH (t:TTP) WHERE NOT coalesce(t.is_revoked, false) RETURN count(t) AS total_ttps }
CALL { MATCH (i:IOC) RETURN count(i) AS total_iocs }
CALL { MATCH (a:Article) RETURN count(a) AS total_articles }
CALL {
  MATCH (a:Article) WHERE a.fetched_at >= $today_start
  RETURN count(a) AS articles_today
}
CALL {
  MATCH (a:Article) WHERE a.fetched_at >= $week_start
  RETURN count(a) AS articles_week
}
RETURN total_cves, critical_cves, high_cves, medium_cves, low_cves, unknown_cves,
       active_exploits, total_actors, total_malware, total_ttps, total_iocs,
       total_articles, articles_today, articles_week
"""


def fetch_stats(tx, *, today_start: str, week_start: str) -> dict:
    row = tx.run(_STATS_QUERY, today_start=today_start, week_start=week_start).single()
    data = dict(row)
    data["severity_distribution"] = {
        "critical": data["critical_cves"], "high": data["high_cves"],
        "medium": data["medium_cves"], "low": data["low_cves"],
        "unknown": data["unknown_cves"],
    }
    # No historical snapshot store exists yet (technical-specification.md §11 doesn't cover
    # one) -- an honest zero, not a fabricated trend, per this codebase's "honest default"
    # convention (e.g. created == modified on first STIX export in L5).
    data["trend_deltas"] = {
        "critical_cves": 0, "active_exploits": 0, "articles_today": 0, "total_actors": 0,
    }
    return data


_TOP_CVES_QUERY = """
MATCH (n:CVE)
WHERE NOT coalesce(n.is_revoked, false)
OPTIONAL MATCH (n)-[:EXPLOITED_BY]->(exploiter)
WITH n, count(DISTINCT exploiter) AS exploiter_count
RETURN elementId(n) AS id, n.cve_id AS cve_id, n.description AS description,
       n.cvss_score AS cvss_score, n.epss_score AS epss_score,
       n.exploited_in_wild AS exploited_in_wild, n.severity_score AS severity_score,
       n.severity_band AS severity_band, n.relevance_score AS relevance_score,
       n.published_date AS published_date, exploiter_count
ORDER BY n.severity_score IS NULL, n.severity_score DESC
LIMIT $limit
"""


def fetch_top_cves(tx, *, limit: int) -> list[dict]:
    return [dict(r) for r in tx.run(_TOP_CVES_QUERY, limit=limit)]


_TOP_ACTORS_QUERY = """
MATCH (n:ThreatActor)
WHERE NOT coalesce(n.is_revoked, false)
RETURN elementId(n) AS id, n.name AS name, n.mitre_id AS mitre_id,
       n.origin_country AS origin_country, n.motivation AS motivation,
       n.relevance_score AS relevance_score, n.confidence AS confidence,
       n.active_since AS active_since
ORDER BY n.relevance_score DESC
LIMIT $limit
"""


def fetch_top_actors(tx, *, limit: int) -> list[dict]:
    return [dict(r) for r in tx.run(_TOP_ACTORS_QUERY, limit=limit)]


_TOP_MALWARE_QUERY = """
MATCH (n:MalwareFamily)
WHERE NOT coalesce(n.is_revoked, false)
RETURN elementId(n) AS id, n.name AS name, n.mitre_id AS mitre_id,
       n.malware_type AS malware_type, n.relevance_score AS relevance_score,
       n.confidence AS confidence
ORDER BY n.relevance_score DESC
LIMIT $limit
"""


def fetch_top_malware(tx, *, limit: int) -> list[dict]:
    return [dict(r) for r in tx.run(_TOP_MALWARE_QUERY, limit=limit)]


_RECENT_STORIES_QUERY = """
MATCH (a:Article)
WHERE a.is_cluster_representative = true AND a.story_cluster_id IS NOT NULL
OPTIONAL MATCH (a)-[:MENTIONS]->(entity)
WITH a, collect(DISTINCT {labels: labels(entity), props: properties(entity)})[0..5] AS entities
RETURN elementId(a) AS id, a.story_cluster_id AS cluster_id, a.title AS headline,
       coalesce(a.dedup_cluster_size, 1) AS article_count, a.published_at AS created_at,
       entities
LIMIT $fetch_limit
"""

# `Article.published_at` is not a uniform format in production (see
# src/nlp/dedup/similarity.py's `_parse_timestamp` docstring): ISO 8601 from this
# codebase's own writers, or a raw RFC 822 string straight from feedparser. Cypher's
# `ORDER BY` sorts lexicographically and would silently misorder a mix of the two, so
# ordering happens in Python via `chronological_sort_key`, over a bounded superset
# fetched from Cypher (over-fetch factor below; cheap at this graph's current volume).
_RECENT_STORIES_OVERFETCH_FACTOR = 5


def _created_at_str(value) -> str | None:
    """Cypher may hand back a plain str (the real writers' shape) or a native
    `neo4j.time.DateTime` (e.g. a test fixture using Cypher `datetime(...)`).
    `chronological_sort_key` only accepts `str | None`, so normalize here."""
    if value is None or isinstance(value, str):
        return value
    return value.isoformat()


def fetch_recent_stories(tx, *, limit: int) -> list[dict]:
    rows = tx.run(
        _RECENT_STORIES_QUERY, fetch_limit=limit * _RECENT_STORIES_OVERFETCH_FACTOR
    )
    stories = []
    for row in rows:
        story = dict(row)
        story["entities"] = [
            {
                "type": entity_short_type(e["labels"]),
                "id": _entity_display_id(e["labels"], e["props"]),
                "name": e["props"].get("name"),
            }
            for e in story["entities"]
            if e["labels"]
        ]
        stories.append(story)
    # Sort by parsed timestamp descending (most recent first). Sorting on just the
    # `datetime` half of `chronological_sort_key`'s tuple (not the leading sentinel
    # bool) is deliberate: `datetime.min` is smaller than every real timestamp, so a
    # plain descending sort already pushes date-less articles to the end on its own --
    # reversing the full tuple would instead put them first (the bool flips too).
    stories.sort(
        key=lambda s: chronological_sort_key(_created_at_str(s["created_at"]))[1],
        reverse=True,
    )
    return stories[:limit]


_SUBGRAPH_QUERY = """
MATCH (n) WHERE elementId(n) = $element_id
OPTIONAL MATCH (n)-[r]-(neighbor)
RETURN elementId(n) AS node_id, labels(n) AS node_labels, properties(n) AS node_props,
       collect(DISTINCT CASE WHEN neighbor IS NULL THEN null ELSE
         {id: elementId(neighbor), labels: labels(neighbor), props: properties(neighbor)}
       END) AS raw_neighbors,
       collect(DISTINCT CASE WHEN r IS NULL THEN null ELSE
         {type: type(r), props: properties(r),
          source: elementId(startNode(r)), target: elementId(endNode(r))}
       END) AS raw_edges
"""


def fetch_subgraph(tx, *, element_id: str) -> dict | None:
    row = tx.run(_SUBGRAPH_QUERY, element_id=element_id).single()
    if row is None or not row["node_labels"]:
        return None
    node_labels = row["node_labels"]
    neighbors = [
        {
            "id": n["id"], "type": entity_subgraph_type(n["labels"]),
            "props": n["props"],
        }
        for n in row["raw_neighbors"] if n is not None
    ]
    edges = [e for e in row["raw_edges"] if e is not None]
    return {
        "node": {
            "id": row["node_id"],
            "type": entity_subgraph_type(node_labels), "labels": node_labels,
            "props": row["node_props"],
        },
        "neighbors": neighbors,
        "edges": edges,
    }
