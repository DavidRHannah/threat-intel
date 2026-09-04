# Architecture

This platform is a serverless, event-driven pipeline. Layers communicate with each other through two mechanisms:

- **`graph-writes`** A shared notification topic for graph changes where subscribers filter by event type.
- **NLP queues** - Consists of extraction, resolution, deduplication, and inference queues that each hand work to the next stage.

## The pipeline

```mermaid
flowchart LR
    subgraph L1["Collection"]
        RSS["RSS/Atom Poller"]
        REST["REST Pollers\n(NVD, EPSS, KEV, GHSA, OTX, abuse.ch)"]
        STIX["ATT&CK Sync"]
    end

    subgraph L2["Text Processing"]
        EXT["Extraction"]
        RES["Resolution"]
        DEDUP["Dedup"]
        INF["Inference"]
    end

    GRAPH[("Neo4j Graph")]
    GW(("graph-writes\nnotifications"))

    subgraph L4["Scoring"]
        SC_EVT["quick update"]
        SC_SWEEP["daily recheck"]
    end

    subgraph ASSETS["Assets"]
        AS_EVT["quick update"]
        AS_SWEEP["daily recheck"]
    end

    subgraph L5["STIX/TAXII Export"]
        WATERMARK["timestamp writer"]
        TAXII["export API"]
    end

    DELIVERY["Dashboard API"]
    UI["React Dashboard"]

    RSS --> EXT
    REST --> GRAPH
    STIX --> GRAPH
    GRAPH -- "new article" --> GW
    GW --> EXT
    EXT --> RES
    RES --> DEDUP
    DEDUP --> INF
    RES --> GRAPH
    INF --> GRAPH
    GRAPH -- "graph changed" --> GW
    GW --> SC_EVT
    GW --> AS_EVT
    GW --> WATERMARK
    SC_EVT --> GRAPH
    SC_SWEEP <--> GRAPH
    AS_EVT --> GRAPH
    AS_SWEEP <--> GRAPH
    WATERMARK --> GRAPH
    TAXII <--> GRAPH
    DELIVERY <--> GRAPH
    DELIVERY --> UI
```

## Event updates and sweeps

Scoring and asset matching have two paths:

- **Event handler:** updates affected records after a graph change.
- **Daily sweep:** recalculates all records, catches missed events, and removes stale asset matches.

Both paths are safe to retry.

## Brief overview of the pieces

| Stage | Code | What it does |
|---|---|---|
| Collection | `src/collection` | Pulls in raw articles for text processing and writes reference data directly to the graph |
| Text Processing | `src/nlp` | Finds entities in text, matches them to known records, groups related articles, and infers relationships |
| Graph writes | `src/common/graph` | Shared graph write and notification code |
| Scoring | `src/scoring` | Rates severity, relevance, and confidence |
| STIX/TAXII Export | `src/interop` | Publishes the graph in a standard threat-intel exchange format |
| Dashboard API | `src/delivery` | The read/write API behind the dashboard |
| Assets | `src/assets` | Matches a user's own software inventory against known vulnerabilities |

See [Data Model](data-model.md) for stored entities and [Lambda Handlers](handlers.md) for triggers and routes.
