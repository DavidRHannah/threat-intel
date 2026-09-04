# Runbook

## Local setup

Requires Python 3.12 and Docker.

```bash
pip install -e ".[dev]"
docker compose up -d   # local Neo4j + local DynamoDB
pytest
```

Local services:

- **Neo4j** on `7474`/`7687`, login `neo4j` / `crossroads-dev`.
- **DynamoDB Local** on `8000`.

## How config values get read

`src/common/config.py:get_config(name, default)` resolves settings in this order:

1. An environment variable, if one's set for it.
2. A given default value, if running locally.
3. Otherwise, a value stored in AWS Parameter Store.
4. If not found there either, the given default value.

Source credentials follow the same pattern. 
Do not put credentials in `config/`; use Parameter Store for deployed environments.

## Config files 

Location: `config/`

These files are version-controlled and become Lambda environment variables at deploy
time.

| File | Used by | Covers |
|---|---|---|
| `config/sources.yaml` | Data collection | Which feeds/sources to poll |
| `config/scoring.yaml` | Scoring | Severity/relevance/confidence weights |
| `config/interop.yaml` | STIX/TAXII export | Export thresholds, ID settings |
| `config/delivery.yaml` | Dashboard API | Page sizes, heatmap tuning |

Values marked `# spike` are the default values.

Removing a source stops future polling.
Existing Neo4j source records are marked inactive to preserve article provenance.

## Deploying

```bash
python -m infra.app   # CDK app sanity check
cdk deploy --all --context env=<env-name>
```

`env` defaults to `dev` and is included in stack names. 

See [Infrastructure](infra.md) for more information on the deployed resources.

## Docs site

You can host this documentation locally or build it and view it in a web browser.

```bash
pip install -e ".[docs]"
mkdocs serve   # http://127.0.0.1:8000
mkdocs build   # static site in ./site
```

The code reference is generated from docstrings during the build.
