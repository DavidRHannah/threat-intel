"""AlienVault OTX (Open Threat Exchange) normalizer (L1 Task 9).

Each OTX "pulse" is a bundle of indicators an analyst has grouped as related to one
campaign/threat. Per pulse:

- An indicator of type `CVE` is a *CVE reference*, not an IOC -- lazy-`MERGE` a CVE stub
  if unseen and trigger on-demand NVD enrichment (FR-DC-22, same trigger pattern as
  CISA KEV/GHSA) via `src.collection.rest.nvd.enrich_cve`.
- Every other indicator `MERGE`s an `IOC` node keyed on the synthetic
  `{value_type_key: ioc_key(value, ioc_type)}` (`src.common.natural_keys` -- never the
  raw `(value, ioc_type)` pair; `UNIQUE` ignores nulls).
- **Reconciled with L3** (`plans/01-data-collection.md` Task 9's blockquote, confirmed
  2026-07-18): a pulse's co-occurrence of IOCs and a CVE tag is itself intelligence --
  "these IOCs indicate this vulnerability is being actively exploited" -- so each
  non-CVE IOC in a pulse gets an `INDICATES` edge (IOC->CVE per
  `technical-specification.md` §3.2; `validate_edge_direction` enforces this, never
  `ASSOCIATED_WITH`), written via
  `src.common.graph.assertion_edges.upsert_authoritative_assertion` inside
  `session.execute_write(...)` and announced via `publish_graph_write`.
  **Scoped to pulses with exactly one CVE tag** (task-9 review finding, 2026-07-22): a
  pulse with one CVE tag plausibly has every one of its IOCs indicating that single CVE
  (the common OTX pattern of a pulse built around one vulnerability), so all its IOCs get
  an edge to that CVE. A pulse with zero CVE tags has nothing to indicate. A pulse with
  two or more CVE tags does **not** get any `INDICATES` edges: which IOC indicates which
  CVE is ambiguous from OTX's flat tag list alone, and writing an edge from every IOC to
  every CVE would be an unjustified cross-product, not a real relationship. Revisit if
  OTX ever exposes a per-indicator CVE association instead of a flat per-pulse tag list.
  `ASSOCIATED_WITH` (ThreatActor/Campaign->IOC) is deliberately NOT written here: this
  task's scope (`FR-DC-01 (Must, for IOC, MalwareFamily, CVE stubs)`) does not include
  ThreatActor/Campaign node creation, and OTX's `adversary`/`tags` fields are free text
  with no reliable canonical-name resolution -- that belongs to a future task with its
  own entity-resolution design, not a silent guess here.

Credentials: `load_credential("otx", "api_key")` -- never hardcoded (FR-DC-18).

FR-DC-22, FR-DC-01 (IOC, CVE stub).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from src.collection.rest.http_errors import handle_response
from src.collection.rest.normalizer import NodeUpsert, read_source_credibility_score
from src.collection.rest.nvd import enrich_cve
from src.collection.rest.ssm_credentials import load_credential
from src.common import natural_keys
from src.common.config import get_config
from src.common.graph.assertion_edges import upsert_authoritative_assertion
from src.common.graph.publish import publish_graph_write

SOURCE_ID = "otx"

_TYPE_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "URI": "url",
    "FileHash-MD5": "md5_hash",
    "FileHash-SHA1": "sha1_hash",
    "FileHash-SHA256": "sha256_hash",
}


class _HttpClient(Protocol):
    def get(self, url: str, params: dict | None = None, headers: dict | None = None) -> Any: ...


def _ioc_type(otx_type: str) -> str:
    return _TYPE_MAP.get(otx_type, otx_type.lower())


@dataclass
class ParsedPulse:
    pulse_id: str
    ioc_values: list[tuple[str, str]] = field(default_factory=list)  # (value, ioc_type)
    cve_ids: list[str] = field(default_factory=list)


def _otx_url() -> str:
    base = get_config("otx_api_base_url", default="https://otx.alienvault.com/api/v1")
    return f"{base}/pulses/subscribed"


def _otx_schema_valid(body: Any) -> bool:
    return isinstance(body, dict) and isinstance(body.get("results"), list)


class OtxNormalizer:
    """Maps an OTX pulse-page response into parsed pulses / NodeUpserts.

    Implements the `SourceNormalizer` protocol via `normalize`; `parse` exposes the
    per-pulse grouping (IOCs + CVE ids) the INDICATES-edge write needs.
    """

    def parse(self, raw_response: dict) -> list[ParsedPulse]:
        out: list[ParsedPulse] = []
        for pulse in raw_response.get("results", []):
            pulse_id = pulse.get("id")
            if not pulse_id:
                continue
            ioc_values: list[tuple[str, str]] = []
            cve_ids: list[str] = []
            for indicator in pulse.get("indicators", []):
                value = indicator.get("indicator")
                otx_type = indicator.get("type")
                if not value or not otx_type:
                    continue
                if otx_type == "CVE":
                    cve_ids.append(value)
                else:
                    ioc_values.append((value, _ioc_type(otx_type)))
            out.append(ParsedPulse(pulse_id=pulse_id, ioc_values=ioc_values, cve_ids=cve_ids))
        return out

    def normalize(self, raw_response: dict) -> list[NodeUpsert]:
        upserts: list[NodeUpsert] = []
        for pulse in self.parse(raw_response):
            for value, ioc_type in pulse.ioc_values:
                upserts.append(
                    NodeUpsert(
                        label="IOC",
                        natural_key={"value_type_key": natural_keys.ioc_key(value, ioc_type)},
                        properties={"value": value, "ioc_type": ioc_type},
                    )
                )
            for cve_id in pulse.cve_ids:
                upserts.append(NodeUpsert(label="CVE", natural_key={"cve_id": cve_id}, properties={}))
        return upserts


def _merge_ioc_tx(tx, value: str, ioc_type: str) -> None:
    key = natural_keys.ioc_key(value, ioc_type)
    tx.run(
        "MERGE (i:IOC {value_type_key: $key}) SET i.value = $value, i.ioc_type = $ioc_type",
        key=key, value=value, ioc_type=ioc_type,
    ).consume()


def _apply_cve_tx(tx, cve_id: str) -> str:
    row = tx.run("MATCH (c:CVE {cve_id:$id}) RETURN c", id=cve_id).single()
    outcome = "existing" if row is not None else "created"
    tx.run("MERGE (c:CVE {cve_id:$id})", id=cve_id).consume()
    return outcome


def _write_pulse_indicates_edges_tx(
    tx, *, ioc_values: list[tuple[str, str]], cve_id: str, now
) -> list[tuple[str, str, str]]:
    """Write every IOC->CVE `INDICATES` edge for a single-CVE pulse inside ONE
    transaction (one `session.execute_write` per pulse, not one per edge pair).

    Only called when a pulse has exactly one CVE tag -- see the module docstring for why
    multi-CVE pulses are skipped entirely rather than writing a cross-product.

    Returns (value, ioc_type, outcome) per edge so the caller can announce each one via
    `publish_graph_write` after the transaction commits.
    """
    credibility_score = read_source_credibility_score(tx, SOURCE_ID)
    results: list[tuple[str, str, str]] = []
    for value, ioc_type in ioc_values:
        outcome = upsert_authoritative_assertion(
            tx,
            start_label="IOC",
            start_key={"value_type_key": natural_keys.ioc_key(value, ioc_type)},
            end_label="CVE",
            end_key={"cve_id": cve_id},
            rel_type="INDICATES",
            feed_source=SOURCE_ID,
            credibility_score=credibility_score,
            now=now,
        )
        results.append((value, ioc_type, outcome))
    return results


def _alert(_response: Any) -> None:
    # A 401/403 from OTX means the API key is invalid/revoked -- a hard config error
    # surfaced via the raised NoRetryError; nothing else to publish here.
    pass


def process_otx(driver, http_client: _HttpClient, nvd_http_client: _HttpClient, *, now) -> int:
    """Fetch subscribed OTX pulses, MERGE each pulse's IOCs and lazy-create/enrich any
    referenced CVEs (FR-DC-22), then -- for pulses with exactly one CVE tag only -- write
    an `INDICATES` edge from every IOC in the pulse to that one CVE (one transaction per
    pulse), announced via `publish_graph_write`. Pulses with zero or 2+ CVE tags write no
    `INDICATES` edges (see module docstring). Returns the count of newly-created CVE stubs.
    """
    api_key = load_credential(SOURCE_ID, "api_key")
    response = http_client.get(_otx_url(), headers={"X-OTX-API-KEY": api_key})
    body = handle_response(response, alert_fn=_alert, schema_validator=_otx_schema_valid)

    pulses = OtxNormalizer().parse(body)
    newly_created: list[str] = []
    with driver.session() as session:
        for pulse in pulses:
            for value, ioc_type in pulse.ioc_values:
                session.execute_write(_merge_ioc_tx, value, ioc_type)
            for cve_id in pulse.cve_ids:
                outcome = session.execute_write(_apply_cve_tx, cve_id)
                if outcome == "created":
                    newly_created.append(cve_id)

    for cve_id in newly_created:
        enrich_cve(driver, nvd_http_client, cve_id)

    with driver.session() as session:
        for pulse in pulses:
            if len(pulse.cve_ids) != 1:
                # Multi-CVE pulses: which IOC indicates which CVE is ambiguous from OTX's
                # flat tag list alone; skip rather than write a false cross-product.
                # Revisit if OTX exposes per-indicator CVE association. Zero-CVE pulses:
                # nothing to indicate.
                continue
            cve_id = pulse.cve_ids[0]
            edges = session.execute_write(
                _write_pulse_indicates_edges_tx,
                ioc_values=pulse.ioc_values,
                cve_id=cve_id,
                now=now,
            )
            for value, ioc_type, outcome in edges:
                publish_graph_write(
                    rel_type="INDICATES",
                    start_key={"value_type_key": natural_keys.ioc_key(value, ioc_type)},
                    end_key={"cve_id": cve_id},
                    outcome=outcome,
                    origin="authoritative",
                    start_label="IOC",
                    end_label="CVE",
                    event_time=now,
                )

    return len(newly_created)


def handler(event=None, context=None, *, driver=None, http_client: _HttpClient | None = None) -> dict:
    """Lambda entry point for the hourly OTX pull (Standard/hourly tier).

    One `httpx` client serves both the OTX pulse fetch and on-demand NVD enrichment of
    newly-referenced CVEs. `now` is the transaction clock for the `INDICATES` edge
    upserts (`publish_graph_write` resolves the topic ARN via `get_config`, populated by
    the CDK stack as an env var). Seams are injectable for tests.
    """
    close_client = False
    if http_client is None:
        import httpx

        http_client = httpx.Client()
        close_client = True
    if driver is None:
        from src.common.neo4j_driver import get_driver

        driver = get_driver()

    try:
        created = process_otx(
            driver, http_client, http_client, now=datetime.now(timezone.utc)
        )
        return {"cves_created": created}
    finally:
        if close_client:
            http_client.close()
