# Repo Tour

Use this page to find the code you need. Read [Architecture](architecture.md) first if you are new to this repository.

## Start here

| Need to change | Start with |
|---|---|
| Graph schema or writes | `src/common/schema_bootstrap.py`, `src/common/graph/` |
| RSS and external feeds | `src/collection/` |
| Entity extraction and relationships | `src/nlp/` |
| Scores | `src/scoring/` |
| Asset-to-CVE matching | `src/assets/` |
| TAXII/STIX export | `src/interop/` |
| Dashboard API | `src/delivery/` |
| AWS resources and triggers | `infra/app.py`, then `infra/stacks/` |

## How data moves

1. Collectors save articles and reference data to Neo4j, publishing a `graph-writes` notification for each write.
2. A new article's notification sends it through extraction, resolution, deduplication, and inference, each of which writes back to Neo4j and publishes its own notification.
3. Scoring, asset matching, and the export watermark react to relevant notifications along the way.
4. Scheduled sweeps recompute scores and asset matches as a safety net.

The NLP stages communicate through queues. Most other reactions use filtered subscriptions to `graph-writes`.

## Shared conventions

- **Natural keys:** repeat writes update the same node or edge instead of creating duplicates.
- **Pure logic first:** matching and scoring calculations live outside handlers where possible.
- **Fast path + sweep:** event handlers improve freshness; daily sweeps restore complete state.
- **Edge types matter:** assertion edges affect relevance; provenance and category edges do not.
- **Configuration:** `get_config()` reads environment variables locally and Parameter Store in AWS.

## Useful tests

Tests mirror the source tree. Run a focused area while working:

```bash
pytest tests/nlp
pytest tests/scoring
pytest tests/infra
```

For deployed entry points and schedules, see [Lambda Handlers](handlers.md). For local setup and deployment, see the [Runbook](runbook.md).
