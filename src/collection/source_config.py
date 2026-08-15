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
from decimal import Decimal

import yaml

_NEO4J_FIELDS = (
    "source_id",
    "name",
    "type",
    "category",
    "credibility_score",
    "polling_tier",
)

_REQUIRED_FIELDS = (
    "source_id",
    "url",
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
    dynamodb_deleted: int = 0


@dataclass
class SyncPlan:
    """What `sync_sources` WOULD do, computed without writing anything.

    `sync_sources` deletes DynamoDB rows absent from the config, which orphans the
    provenance of any Article already carrying that source_id, so the destructive half
    needs to be previewable before it runs.
    """

    to_create: list[str]
    to_update: list[str]
    to_delete: list[str]


def _load_config(config_path: str) -> list[dict]:
    with open(config_path) as f:
        entries = yaml.safe_load(f)
    entries = entries or []
    for entry in entries:
        for field in _REQUIRED_FIELDS:
            if entry.get(field) is None:
                raise ValueError(
                    f"config entry {entry.get('source_id', '<unknown>')!r} is missing "
                    f"required field {field!r}"
                )
    return entries


def plan_sync(config_path: str, dynamodb_table) -> SyncPlan:
    """Read-only preview of `sync_sources`'s DynamoDB reconciliation."""
    entries = _load_config(config_path)
    existing = {row["source_id"] for row in dynamodb_table.scan()["Items"]}
    config_ids = [entry["source_id"] for entry in entries]

    return SyncPlan(
        to_create=[sid for sid in config_ids if sid not in existing],
        to_update=[sid for sid in config_ids if sid in existing],
        to_delete=sorted(existing - set(config_ids)),
    )


def _for_dynamodb(entry: dict) -> dict:
    """DynamoDB rejects Python floats, and credibility_score is a float in YAML.

    Decimal(str(v)) rather than Decimal(v): the latter carries the full binary
    expansion of the float (0.9 -> 0.90000000000000002220446...), which DynamoDB
    rejects for exceeding 38 digits of precision.
    """
    return {
        key: Decimal(str(value)) if isinstance(value, float) else value
        for key, value in entry.items()
    }


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
        dynamodb_table.put_item(Item=_for_dynamodb(entry))

    deactivated = 0
    for source_id in existing:
        if source_id not in config_ids:
            dynamodb_table.delete_item(Key={"source_id": source_id})
            deactivated += 1

    return created, updated, deactivated


def _sync_neo4j(entries: list[dict], driver) -> int:
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

        result = session.execute_write(
            lambda tx: tx.run(
                "MATCH (s:Source) WHERE NOT s.source_id IN $config_ids "
                "AND s.is_active = true "
                "SET s.is_active = false "
                "RETURN count(s) AS n",
                config_ids=config_ids,
            ).single()
        )
        return result["n"]


def sync_sources(config_path: str, dynamodb_table, driver) -> SyncResult:
    entries = _load_config(config_path)

    created, updated, dynamodb_deleted = _sync_dynamodb(entries, dynamodb_table)
    deactivated = _sync_neo4j(entries, driver)

    return SyncResult(
        created=created,
        updated=updated,
        deactivated=deactivated,
        dynamodb_deleted=dynamodb_deleted,
    )
