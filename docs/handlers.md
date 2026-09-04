# Lambda Handlers

This page contains the details regarding the function of every lambda used in the codebase. For the full source, see the Code Reference nav.

## Collection

Location: `infra/stacks/data_collection_stack.py`

| Handler | Runs | Does |
|---|---|---|
| `collection/rss/poller.py` | Every 10 min | Checks RSS/Atom feeds for new articles |
| `collection/rss/extraction.py` | On new discovery-updates message | Fetches full article text, saves the `Article` node, and announces it on `graph-writes` |
| `collection/rest/abusech.py` (URLhaus, MalwareBazaar, ThreatFox) | Every 15 min | Pulls new/changed data from each source |
| `collection/rest/nvd.py`, `ghsa.py`, `otx.py` | Hourly | Pulls new/changed data from each source |
| `collection/rest/cisa_kev.py` | Daily | Pulls new/changed data from the source |
| `collection/rest/epss.py` | Daily | Refreshes EPSS scores |
| `collection/stix/attck_sync.py` | Daily | Re-syncs MITRE ATT&CK data when it's updated |

## Text Processing

Location: `infra/stacks/nlp_stack.py`

| Handler | Runs | Does |
|---|---|---|
| `nlp/extraction/handler.py` | When a new article is saved | Finds entities mentioned in the text |
| `nlp/resolution/handler.py` | After extraction | Matches mentions to known records |
| `nlp/dedup/handler.py` | After resolution | Groups articles covering the same story |
| `nlp/inference/handler.py` | After dedup | Infers relationships from each story |

## Scoring

Location: `infra/stacks/scoring_stack.py`

| Handler | Runs | Does |
|---|---|---|
| `scoring/event_handler.py` | On graph changes | Quick score update |
| `scoring/sweep_handler.py` | Daily | Recalculates every score from scratch |

## Assets

Location: `infra/stacks/assets_stack.py`

| Handler | Runs | Does |
|---|---|---|
| `assets/event_handler.py` | On graph changes | Matches new vulnerability data against user assets |
| `assets/sweep_handler.py` | Daily | Rechecks all matches, adds new ones, and removes stale ones |

## STIX/TAXII Export

Location: `infra/stacks/interop_stack.py`

| Handler | Route / Trigger | Does |
|---|---|---|
| `interop/taxii_handler.py` | `GET /taxii2` | Lists what's available to export |
| `interop/taxii_handler.py` | `GET /taxii2/api/collections` | Lists export collections |
| `interop/taxii_handler.py` | `GET /taxii2/api/collections/{collection_id}/objects` | Returns the data itself, built fresh on each request |
| `interop/watermark_handler.py` | On graph changes | Timestamps each write so exports can track what's new |

## Dashboard API

Location: `infra/stacks/delivery_stack.py`

| Handler | Route | Does |
|---|---|---|
| `delivery/dashboard_handler.py` | `GET /dashboard/stats` | Summary counters |
| `delivery/dashboard_handler.py` | `GET /dashboard/top-cves` | Top-scored CVEs |
| `delivery/dashboard_handler.py` | `GET /dashboard/top-actors` | Top threat actors |
| `delivery/dashboard_handler.py` | `GET /dashboard/top-malware` | Top malware families |
| `delivery/dashboard_handler.py` | `GET /dashboard/top-campaigns` | Top campaigns |
| `delivery/dashboard_handler.py` | `GET /dashboard/recent-stories` | Recently grouped stories |
| `delivery/dashboard_handler.py` | `GET /dashboard/subgraph/{id}` | Everything connected to one item |
| `delivery/ttp_heatmap_handler.py` | `GET /dashboard/ttp-heatmap` | Which techniques are trending, and how much |
| `delivery/search_handler.py` | `GET /search` | Text search across CVEs, actors, malware, campaigns |
| `delivery/assets_handler.py` | `POST /assets` | Add an asset |
| `delivery/assets_handler.py` | `GET /assets` | List assets |
| `delivery/assets_handler.py` | `DELETE /assets/{id}` | Remove an asset |
| `delivery/assets_handler.py` | `GET /assets/{id}/cves` | CVEs matched to one asset |
| `delivery/assets_handler.py` | `GET /assets/cves` | CVEs matched across all assets |
| `delivery/assets_handler.py` | `GET /assets/known-vendor-products` | Autocomplete for adding an asset |

Every dashboard route is read-only except for adding/removing assets.

## Setup

| Handler | Runs | Does |
|---|---|---|
| `common/schema_bootstrap_handler.py` | On stack creation, and again whenever the schema changes | Sets up the Neo4j schema |
