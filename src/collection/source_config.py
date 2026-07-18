"""Deploy-time sync of config/sources.yaml into DynamoDB and Neo4j.

FR-DC-16: config/sources.yaml is the git-tracked source of truth for feeds. sync_sources
reconciles it into both stores on each deploy. The two stores are deliberately asymmetric:

- DynamoDB (the `Sources` table) is a live mirror: a source removed from config is
  `delete_item`'d.
- Neo4j (`Source` nodes) preserves provenance ("flag, don't delete", NFR-DATA-03): a source
  removed from config is `SET is_active = false`, never `DETACH DELETE`'d, because Article
  nodes may still point at it via PUBLISHED_BY.
"""
from dataclasses import dataclass

import yaml

_NEO4J_FIELDS = (
    "source_id",
    "name",
    "type",
    "category",
    "credibility_score",
    "polling_tier",
)


@dataclass
class SyncResult:
    created: int
    updated: int
    deactivated: int


def _load_config(config_path: str) -> list[dict]:
    with open(config_path) as f:
        entries = yaml.safe_load(f)
    return entries or []


def _sync_dynamodb(entries: list[dict], dynamodb_table) -> tuple[int, int, int]:
    existing = {row["source_id"]: row for row in dynamodb_table.scan()["Items"]}
    config_ids = {entry["source_id"] for entry in entries}

    created = 0
    updated = 0
    for entry in entries:
        if entry["source_id"] in existing:
            updated += 1
        else:
            created += 1
        dynamodb_table.put_item(Item=entry)

    deactivated = 0
    for source_id in existing:
        if source_id not in config_ids:
            dynamodb_table.delete_item(Key={"source_id": source_id})
            deactivated += 1

    return created, updated, deactivated


def _sync_neo4j(entries: list[dict], driver) -> None:
    config_ids = [entry["source_id"] for entry in entries]

    with driver.session() as session:
        for entry in entries:
            params = {field: entry.get(field) for field in _NEO4J_FIELDS}
            params["url"] = entry["url"]
            session.execute_write(
                lambda tx, params=params: tx.run(
                    "MERGE (s:Source {url: $url}) "
                    "SET s.source_id = $source_id, s.name = $name, s.type = $type, "
                    "s.category = $category, s.credibility_score = $credibility_score, "
                    "s.polling_tier = $polling_tier, s.is_active = true",
                    **params,
                ).consume()
            )

        session.execute_write(
            lambda tx: tx.run(
                "MATCH (s:Source) WHERE NOT s.source_id IN $config_ids "
                "SET s.is_active = false",
                config_ids=config_ids,
            ).consume()
        )


def sync_sources(config_path: str, dynamodb_table, driver) -> SyncResult:
    entries = _load_config(config_path)

    created, updated, deactivated = _sync_dynamodb(entries, dynamodb_table)
    _sync_neo4j(entries, driver)

    return SyncResult(created=created, updated=updated, deactivated=deactivated)
