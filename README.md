# Crossroads

An open-source threat-intelligence platform, built as a Feedly Threat Intelligence clone.

Crossroads ingests security feeds and turns them into a queryable, scored threat graph:

- Collects data from RSS/Atom feeds, security blogs, CERT/CISA advisories, NVD, MITRE ATT&CK, and abuse.ch
- Extracts CVEs, IOCs, threat actors, and malware families from unstructured text via NLP
- Models entities and relationships in a Neo4j graph (articles, CVEs, actors, TTPs)
- Scores severity, relevance, and confidence, then exports via STIX/TAXII and a RAG-backed Q&A interface

## Building from source

Requires Python 3.12 and Docker (for local Neo4j and DynamoDB).

```bash
pip install -e ".[dev]"
docker compose up -d
pytest
```
