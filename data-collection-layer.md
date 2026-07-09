# Data Collection Layer

Defines the node data model — what each entity looks like once stored in Neo4j. This covers node properties only; relationships/edges between these nodes (e.g. `(:Article)-[:MENTIONS]->(:CVE)`) are documented separately in `relationships-graph-layer.md`.

## Common Fields

Every node below carries these fields in addition to its entity-specific ones.

| Field | Type | Description |
|---|---|---|
| id | uuid | Internal unique identifier |
| first_seen | datetime | When this node was first ingested into the system |
| last_updated | datetime | Last time this node's data was refreshed |
| confidence | float 0-1 | Confidence the entity is correctly resolved/deduplicated |

## Source

The feed/publisher an Article or IOC originated from.

| Field | Type | Description |
|---|---|---|
| name | string | Publisher/feed name |
| url | string | Feed or homepage URL |
| type | enum | `rss`, `blog`, `cert_advisory`, `social`, `structured_feed` |
| category | enum | `vendor`, `government`, `community`, `osint` |
| credibility_score | float 0-1 | Trustworthiness of this source |
| last_polled_at | datetime | Last time this source was crawled |

## Article

A single crawled item, post-deduplication (one story from N feeds collapses to one Article).

| Field | Type | Description |
|---|---|---|
| title | string | Article title |
| url | string | Canonical URL |
| cleaned_text | string | Extracted, cleaned article body |
| summary | string | Short summary |
| content_hash | string | Hash of normalized content, used for dedup matching |
| dedup_cluster_size | int | Number of raw feed items merged into this Article |
| published_at | datetime | Publish timestamp from the source |
| fetched_at | datetime | When the crawler retrieved it |
| author | string | Author name, if available |
| language | string | Detected language code |

## CVE

| Field | Type | Description |
|---|---|---|
| cve_id | string | e.g. `CVE-2026-1234` |
| description | string | Vulnerability description |
| cvss_score | float | CVSS base score |
| cvss_vector | string | CVSS vector string |
| epss_score | float | Exploit Prediction Scoring System probability |
| exploited_in_wild | bool | Whether it appears on CISA's Known Exploited Vulnerabilities list |
| affected_products | [string] | CPE strings for affected products |
| published_date | datetime | NVD publish date |
| last_modified_date | datetime | NVD last-modified date |

## CWE

Common Weakness Enumeration — the weakness category a CVE falls under.

| Field | Type | Description |
|---|---|---|
| cwe_id | string | e.g. `CWE-79` |
| name | string | Weakness name |
| description | string | Weakness description |

## IOC

An Indicator of Compromise (IP, domain, URL, or file hash) sourced from structured feeds like abuse.ch.

| Field | Type | Description |
|---|---|---|
| value | string | The actual indicator value (IP, domain, URL, or hash) |
| ioc_type | enum | `ip`, `domain`, `url`, `md5`, `sha1`, `sha256`, `email` |
| malicious_confidence | float | Feed-provided maliciousness confidence (e.g. from ThreatFox) |
| first_seen_wild | datetime | First time this indicator was observed in the wild, per the feed |
| last_seen_wild | datetime | Most recent observation in the wild, per the feed |
| tags | [string] | Feed-provided tags, e.g. `c2`, `phishing` |

## ThreatActor

| Field | Type | Description |
|---|---|---|
| name | string | Canonical name, e.g. `APT28` |
| aliases | [string] | Other known names, e.g. `Fancy Bear`, `Sofacy` |
| origin_country | string | Attributed country of origin |
| motivation | enum | `espionage`, `financial`, `hacktivism`, etc. |
| active_since | date | Earliest known activity date |
| sophistication_level | enum | e.g. `low`, `medium`, `high`, `advanced` |
| description | string | Profile summary |

## MalwareFamily

| Field | Type | Description |
|---|---|---|
| name | string | Canonical family name |
| aliases | [string] | Other known names |
| malware_type | enum | `ransomware`, `trojan`, `botnet`, `wiper`, `rat`, etc. |
| platforms | [string] | Target platforms, e.g. `windows`, `linux`, `android` |
| first_observed | date | Earliest known observation date |
| description | string | Family summary |

## TTP

A MITRE ATT&CK technique.

| Field | Type | Description |
|---|---|---|
| technique_id | string | e.g. `T1566` |
| sub_technique_id | string, nullable | e.g. `T1566.001` |
| name | string | Technique name |
| tactic | [string] | Associated tactic(s), e.g. `Initial Access` |
| mitre_url | string | Link to the MITRE ATT&CK page |

## Campaign

A named attack campaign or incident tying together CVEs, threat actors, and TTPs over time.

| Field | Type | Description |
|---|---|---|
| name | string | Campaign name |
| aliases | [string] | Other known names |
| start_date | date | Start of observed activity |
| end_date | date, nullable | End of observed activity; null if ongoing |
| objective | string | Apparent goal of the campaign |
| description | string | Campaign summary |
