"""GHSA (GitHub Security Advisories) normalizer (L1 Task 9).

GHSA is the one hybrid Category B source (design Part 4 §1): its structured fields
(severity, identifiers, published date) update/create the linked `CVE` node directly,
while its free-text `description` becomes an `Article` node that flows into the same
NLP hand-off as any RSS article -- it can carry information (a mentioned threat actor,
a campaign) the structured fields don't capture.

- Structured path: for each advisory carrying a `CVE` identifier, lazy-`MERGE` a CVE
  stub if unseen and trigger on-demand NVD enrichment (FR-DC-22, same as CISA KEV) via
  `src.collection.rest.nvd.enrich_cve`; SET GHSA-sourced fields (`ghsa_id`,
  `ghsa_severity`) on the same node. An advisory with **no** CVE identifier yet (GitHub
  assigns some before MITRE/NVD does) still produces its Article -- it just has no CVE
  to link.
- Article path: `MERGE` on `{source_guid_key: article_key("ghsa", <GHSA-ID>)}` (never the
  raw `(source_id, guid)` pair -- `00-infra.md` Task 5's synthetic-key convention), then
  announce it with a **hand-rolled, node-shaped** SNS publish identical in spirit to
  Task 5's RSS Extraction Lambda -- NOT `publish_graph_write`, which is edge-shaped and
  would be silently ignored by L2's Extraction Lambda (it filters on
  `node_label == "Article"` and reads `cleaned_text`/`title` straight off the message).

Credentials: GHSA's GraphQL API needs a GitHub token, loaded via `load_credential("ghsa",
"token")` -- never hardcoded (FR-DC-18).

FR-DC-22, FR-DC-01 (CVE stub, Article).
"""

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from src.collection.rest.http_errors import handle_response
from src.collection.rest.normalizer import NodeUpsert
from src.collection.rest.nvd import enrich_cve
from src.collection.rest.ssm_credentials import load_credential
from src.common import natural_keys
from src.common.config import get_config

SOURCE_ID = "ghsa"


class _HttpClient(Protocol):
    def post(self, url: str, json: dict, headers: dict | None = None) -> Any: ...


@dataclass
class ParsedGhsaAdvisory:
    ghsa_id: str
    cve_id: str | None
    summary: str
    description: str
    severity: str | None
    published_at: str | None
    cve_properties: dict[str, Any] = field(default_factory=dict)


def _ghsa_url() -> str:
    return get_config("ghsa_api_base_url", default="https://api.github.com/graphql")


def _ghsa_schema_valid(body: Any) -> bool:
    return (
        isinstance(body, dict)
        and isinstance(body.get("data"), dict)
        and isinstance(body["data"].get("securityAdvisories"), dict)
        and isinstance(body["data"]["securityAdvisories"].get("nodes"), list)
    )


def _cve_identifier(identifiers: list[dict]) -> str | None:
    for ident in identifiers:
        if ident.get("type") == "CVE":
            return ident.get("value")
    return None


class GhsaNormalizer:
    """Maps a GHSA GraphQL advisories response into parsed advisories / NodeUpserts.

    Implements the `SourceNormalizer` protocol via `normalize`; `parse` exposes the
    richer per-advisory record (Article fields + CVE link) the process path needs.
    """

    def parse(self, raw_response: dict) -> list[ParsedGhsaAdvisory]:
        out: list[ParsedGhsaAdvisory] = []
        nodes = raw_response.get("data", {}).get("securityAdvisories", {}).get("nodes", [])
        for node in nodes:
            ghsa_id = node.get("ghsaId")
            if not ghsa_id:
                continue
            cve_id = _cve_identifier(node.get("identifiers", []) or [])
            cve_props: dict[str, Any] = {"ghsa_id": ghsa_id}
            if node.get("severity"):
                cve_props["ghsa_severity"] = node["severity"]
            out.append(
                ParsedGhsaAdvisory(
                    ghsa_id=ghsa_id,
                    cve_id=cve_id,
                    summary=node.get("summary", ""),
                    description=node.get("description", ""),
                    severity=node.get("severity"),
                    published_at=node.get("publishedAt"),
                    cve_properties=cve_props,
                )
            )
        return out

    def normalize(self, raw_response: dict) -> list[NodeUpsert]:
        upserts: list[NodeUpsert] = []
        for adv in self.parse(raw_response):
            if adv.cve_id:
                upserts.append(
                    NodeUpsert(
                        label="CVE", natural_key={"cve_id": adv.cve_id}, properties=adv.cve_properties
                    )
                )
            upserts.append(
                NodeUpsert(
                    label="Article",
                    natural_key={
                        "source_guid_key": natural_keys.article_key(SOURCE_ID, adv.ghsa_id)
                    },
                    properties={
                        "source_id": SOURCE_ID,
                        "guid": adv.ghsa_id,
                        "title": adv.summary,
                        "cleaned_text": adv.description,
                        "published_at": adv.published_at,
                    },
                )
            )
        return upserts


def _apply_cve_tx(tx, cve_id: str, properties: dict) -> str:
    row = tx.run("MATCH (c:CVE {cve_id:$id}) RETURN c", id=cve_id).single()
    outcome = "existing" if row is not None else "created"
    tx.run("MERGE (c:CVE {cve_id:$id})", id=cve_id).consume()
    if properties:
        tx.run("MATCH (c:CVE {cve_id:$id}) SET c += $props", id=cve_id, props=properties).consume()
    return outcome


def _merge_article_tx(tx, source_guid_key: str, **props: Any) -> None:
    tx.run(
        """
        MERGE (a:Article {source_guid_key: $source_guid_key})
        ON CREATE SET a.dedup_cluster_size = 1
        SET a += $props
        """,
        source_guid_key=source_guid_key,
        props=props,
    ).consume()


def _alert(_response: Any) -> None:
    # A 401/403 from the GHSA GraphQL API means the GitHub token is invalid/expired --
    # a hard config error surfaced via the raised NoRetryError; nothing to publish here.
    pass


def process_ghsa(
    driver,
    http_client: _HttpClient,
    nvd_http_client: _HttpClient,
    *,
    sns_client: Any,
    topic_arn: str,
) -> int:
    """Fetch GHSA advisories, split each into its structured CVE update (lazy-created +
    NVD-enriched if unseen, FR-DC-22) and its Article (hand-rolled node-shaped SNS
    announcement, same as Task 5). Returns the count of newly-created CVE stubs.
    """
    token = load_credential(SOURCE_ID, "token")
    query = (
        "query { securityAdvisories(first: 50) { nodes { ghsaId summary description "
        "severity publishedAt identifiers { type value } } pageInfo { hasNextPage "
        "endCursor } } }"
    )
    response = http_client.post(
        _ghsa_url(), json={"query": query}, headers={"Authorization": f"Bearer {token}"}
    )
    body = handle_response(response, alert_fn=_alert, schema_validator=_ghsa_schema_valid)

    advisories = GhsaNormalizer().parse(body)
    newly_created: list[str] = []
    with driver.session() as session:
        for adv in advisories:
            if adv.cve_id:
                outcome = session.execute_write(_apply_cve_tx, adv.cve_id, adv.cve_properties)
                if outcome == "created":
                    newly_created.append(adv.cve_id)

            source_guid_key = natural_keys.article_key(SOURCE_ID, adv.ghsa_id)
            session.execute_write(
                _merge_article_tx,
                source_guid_key,
                source_id=SOURCE_ID,
                guid=adv.ghsa_id,
                title=adv.summary,
                cleaned_text=adv.description,
                published_at=adv.published_at,
            )

            # Node-shaped announcement for L2's Extraction (NER) Lambda -- deliberately
            # NOT publish_graph_write (see module docstring).
            sns_client.publish(
                TopicArn=topic_arn,
                Message=json.dumps(
                    {
                        "node_label": "Article",
                        "article_id": source_guid_key,
                        "source_id": SOURCE_ID,
                        "guid": adv.ghsa_id,
                        "cleaned_text": adv.description,
                        "title": adv.summary,
                        "published_at": adv.published_at,
                    }
                ),
            )

    for cve_id in newly_created:
        enrich_cve(driver, nvd_http_client, cve_id)

    return len(newly_created)


def handler(
    event=None,
    context=None,
    *,
    driver=None,
    http_client: _HttpClient | None = None,
    sns_client: Any = None,
) -> dict:
    """Lambda entry point for the hourly GHSA pull (Standard/hourly tier).

    One `httpx` client serves both the GHSA GraphQL call and the on-demand NVD
    enrichment of newly-referenced CVEs. The Article announcement is a node-shaped
    `sns.publish` to the `graph-writes` topic (never `publish_graph_write` — see the
    module docstring); the topic ARN is resolved via
    `get_config("graph_writes_topic_arn")`, populated by the CDK stack as an env var.
    Seams are injectable for tests.
    """
    close_client = False
    if http_client is None:
        import httpx

        http_client = httpx.Client()
        close_client = True
    if driver is None:
        from src.common.neo4j_driver import get_driver

        driver = get_driver()
    if sns_client is None:
        import boto3

        sns_client = boto3.client("sns")

    topic_arn = get_config("graph_writes_topic_arn")
    try:
        created = process_ghsa(
            driver, http_client, http_client, sns_client=sns_client, topic_arn=topic_arn
        )
        return {"cves_created": created}
    finally:
        if close_client:
            http_client.close()
