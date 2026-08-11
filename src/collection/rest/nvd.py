"""NVD normalizer — delta poll, lazy CVE creation, on-demand enrichment (L1 Task 8).

Two entry points, both routing their HTTP response through `handle_response` (Task 7):

- `poll_nvd_delta(driver, http_client, last_success_at) -> (int, str)`
  Fetches CVEs modified since `last_success_at` (FR-DC-17) and updates the fields of
  CVEs that ALREADY EXIST in the graph — it never creates a node for a CVE the graph
  has not otherwise referenced (FR-DC-23). Returns `(count of existing CVEs updated,
  window_end)`, where `window_end` is the instant captured before the fetch that the
  handler records as the next poll's watermark (see `handler`).

- `enrich_cve(driver, http_client, cve_id) -> None`
  On-demand single-CVE enrichment. A caller (GHSA/CISA-KEV, Task 9) MERGEs a bare CVE
  stub on `cve_id` when it references an unseen CVE (FR-DC-22); this fetches that one
  CVE from NVD and populates its fields. It MERGEs the CVE itself so it is safe to call
  even if the stub does not yet exist.

Both share one freshness guard on the CATEGORIZED_AS (CVE->CWE) re-sync
(`src.common.graph.structural_edges.resync_categorized_as`). That re-sync is internally
atomic, but two reads of the SAME CVE with DIFFERENT payloads (the scheduled delta poll
and an on-demand `enrich_cve`) can race, and commit order alone decides the outcome: if
the newer payload (a CWE dropped) commits first and the older, stale payload commits
second, the stale one's diff re-creates the dropped mapping — a silently resurrected
edge. A node lock does not fix this (both transactions are individually correct); the
fix is a freshness guard. We carry NVD's own `lastModified` for the CVE and, inside the
SAME `execute_write` transaction that reads the CVE's stored `last_modified_date`, skip
the re-sync (only the re-sync — scalar field SETs still apply) whenever the stored value
is present and is >= the incoming one. When we do apply the re-sync we advance
`last_modified_date` to the incoming value in that same transaction, so the read, the
decision, and both writes are atomic together and no race window reopens.

FR-DC-17, FR-DC-22, FR-DC-23, FR-DC-25, FR-DC-01 (CVE).
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from src.collection.rest.http_errors import handle_response
from src.collection.rest.normalizer import NodeUpsert
from src.common.config import get_config
from src.common.graph.publish import publish_node_write
from src.common.graph.structural_edges import resync_categorized_as


class _HttpClient(Protocol):
    def get(self, url: str, params: dict | None = None) -> Any: ...


@dataclass
class ParsedCve:
    """A single CVE parsed out of an NVD v2.0 response.

    `properties` holds the scalar CVE fields to SET (never `last_modified_date`, which
    the freshness guard owns and writes only when a re-sync is applied). `cwe_ids` and
    `last_modified` are carried separately because a `NodeUpsert` cannot express edge
    re-sync or the freshness watermark.
    """

    cve_id: str
    last_modified: str | None
    properties: dict[str, Any] = field(default_factory=dict)
    cwe_ids: list[str] = field(default_factory=list)


def _nvd_url() -> str:
    base = get_config("nvd_api_base_url", default="https://services.nvd.nist.gov/rest/json/cves")
    version = get_config("nvd_api_version", default="2.0")
    return f"{base}/{version}"


def _english(entries: list[dict]) -> str | None:
    for e in entries:
        if e.get("lang") == "en":
            return e.get("value")
    return entries[0].get("value") if entries else None


def _cvss(metrics: dict) -> tuple[float | None, str | None]:
    # Prefer CVSS v3.1, then v3.0, then v2 — mirrors NVD's own precedence.
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore"), data.get("vectorString")
    return None, None


def _cwe_ids(weaknesses: list[dict]) -> list[str]:
    ids: list[str] = []
    for w in weaknesses:
        for d in w.get("description", []):
            value = d.get("value")
            # NVD emits non-mapping sentinels like "NVD-CWE-noinfo" / "NVD-CWE-Other";
            # only real CWE-<n> identifiers become CWE nodes.
            if value and value.startswith("CWE-") and value[4:].isdigit():
                if value not in ids:
                    ids.append(value)
    return ids


def _affected_products(configurations: list[dict]) -> list[str]:
    products: list[str] = []
    for cfg in configurations:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria")
                if criteria and criteria not in products:
                    products.append(criteria)
    return products


class NvdNormalizer:
    """Maps an NVD v2.0 response into parsed CVE records / NodeUpserts.

    Implements the `SourceNormalizer` protocol via `normalize`; `parse` exposes the
    richer per-CVE record (CWE set + `last_modified`) the poll/enrich paths need.
    """

    def parse(self, raw_response: dict) -> list[ParsedCve]:
        out: list[ParsedCve] = []
        for item in raw_response.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            score, vector = _cvss(cve.get("metrics", {}) or {})
            props: dict[str, Any] = {}
            description = _english(cve.get("descriptions", []) or [])
            if description is not None:
                props["description"] = description
            if score is not None:
                props["cvss_score"] = score
            if vector is not None:
                props["cvss_vector"] = vector
            if cve.get("published"):
                props["published_date"] = cve["published"]
            affected = _affected_products(cve.get("configurations", []) or [])
            if affected:
                props["affected_products"] = affected
            out.append(
                ParsedCve(
                    cve_id=cve_id,
                    last_modified=cve.get("lastModified"),
                    properties=props,
                    cwe_ids=_cwe_ids(cve.get("weaknesses", []) or []),
                )
            )
        return out

    def normalize(self, raw_response: dict) -> list[NodeUpsert]:
        upserts: list[NodeUpsert] = []
        for parsed in self.parse(raw_response):
            props = dict(parsed.properties)
            if parsed.last_modified is not None:
                props["last_modified_date"] = parsed.last_modified
            upserts.append(
                NodeUpsert(label="CVE", natural_key={"cve_id": parsed.cve_id}, properties=props)
            )
        return upserts


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    # Normalize to aware for a total ordering; NVD stamps are naive UTC.
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _is_newer(incoming: str | None, stored: str | None) -> bool:
    """True when the incoming payload should drive a CATEGORIZED_AS re-sync — i.e. nothing
    is stored yet, or the incoming `lastModified` is strictly newer than the stored one.
    Falls back to string comparison if either timestamp is unparseable."""
    if stored is None:
        return True
    if incoming is None:
        return False
    incoming_dt, stored_dt = _parse_dt(incoming), _parse_dt(stored)
    if incoming_dt is not None and stored_dt is not None:
        return incoming_dt > stored_dt
    return incoming > stored


def _apply_cve_tx(tx, parsed: ParsedCve, *, allow_create: bool) -> tuple[str, bool]:
    """Read-decide-write for one CVE, atomically inside a single execute_write callback.

    Returns `(outcome, cvss_changed)`.

    `outcome` is one of: "absent" (delta path, CVE not in graph -> untouched,
    uncounted), "resynced" (fields set + CATEGORIZED_AS re-synced + last_modified_date
    advanced), "stale" (fields set, re-sync SKIPPED because the payload is not newer).

    `cvss_changed` is True only if this call's incoming `cvss_score` differs numerically
    from the value stored BEFORE this write.

    Neo4j takes no read locks: a plain `MATCH ... RETURN` here, in its own transaction,
    does not prevent a second concurrent transaction (`enrich_cve` runs from the NVD,
    GHSA, OTX, and KEV Lambdas over non-FIFO SQS with no reserved concurrency) from
    reading the SAME stale `cvss_score` before this one commits -- which can cause a
    duplicate announce, or, if the concurrent transaction holds a STALE payload, a
    missed announce (it computes `incoming == its own stale read` and stays silent).
    `apoc.lock.nodes([c])` alone is NOT enough: projecting a property off the same binding
    that fed the lock returns what that cursor already saw -- the PRE-lock value -- so the
    lock is present, syntactically correct, and useless (measured: it permitted every one
    of 10 concurrent runners to announce). The deciding reads are therefore issued by a
    SECOND `MATCH` after the lock, whose cursor sees freshly committed state. Same shape as
    `src/scoring/confidence.py`. Do not collapse the two MATCHes back into one."""
    if allow_create:
        row = tx.run(
            "MERGE (c:CVE {cve_id:$id}) "
            "WITH c "
            "CALL apoc.lock.nodes([c]) "
            "WITH c "
            "MATCH (n:CVE {cve_id:$id}) "
            "RETURN n.last_modified_date AS lmd, n.cvss_score AS cvss_score",
            id=parsed.cve_id,
        ).single()
    else:
        row = tx.run(
            "MATCH (c:CVE {cve_id:$id}) "
            "CALL apoc.lock.nodes([c]) "
            "WITH c "
            "MATCH (n:CVE {cve_id:$id}) "
            "RETURN n.last_modified_date AS lmd, n.cvss_score AS cvss_score",
            id=parsed.cve_id,
        ).single()

    if row is None:
        return "absent", False  # FR-DC-23: the delta poll never creates a CVE node.

    stored_lmd = row["lmd"]
    stored_cvss = row["cvss_score"]
    incoming_cvss = parsed.properties.get("cvss_score")
    cvss_changed = incoming_cvss is not None and incoming_cvss != stored_cvss

    # Scalar fields are last-write-wins and always applied (guard scopes to the re-sync
    # only). last_modified_date is deliberately NOT in this SET — it is the watermark.
    if parsed.properties:
        tx.run(
            "MATCH (c:CVE {cve_id:$id}) SET c += $props",
            id=parsed.cve_id,
            props=parsed.properties,
        ).consume()

    if _is_newer(parsed.last_modified, stored_lmd):
        # L3's merge_relationship MATCHes both endpoints and never creates nodes (node
        # creation is the calling layer's job). Nothing else in src/ MERGEs a CWE, so the
        # CVE->CWE re-sync would raise EndpointNotFoundError on any real CVE carrying a CWE.
        # MERGE each CWE stub here, inside this same execute_write transaction, before the
        # re-sync. The cwe_id_unique constraint (schema_bootstrap.py) makes this idempotent.
        for cwe_id in parsed.cwe_ids:
            tx.run("MERGE (:CWE {cwe_id: $id})", id=cwe_id).consume()
        resync_categorized_as(
            tx,
            cve_key={"cve_id": parsed.cve_id},
            cwe_keys=[{"cwe_id": w} for w in parsed.cwe_ids],
        )
        if parsed.last_modified is not None:
            tx.run(
                "MATCH (c:CVE {cve_id:$id}) SET c.last_modified_date=$lmd",
                id=parsed.cve_id,
                lmd=parsed.last_modified,
            ).consume()
        return "resynced", cvss_changed

    return "stale", cvss_changed  # freshness guard: skip the CATEGORIZED_AS re-sync only.


def _alert(_response: Any) -> None:
    # 401/403 from NVD: `handle_response` invokes this before raising NoRetryError. NVD's
    # public API is keyless (a key only raises rate limits), so an auth failure is a hard
    # config error the caller surfaces via the raised NoRetryError; nothing to publish here.
    pass


def poll_nvd_delta(
    driver, http_client: _HttpClient, last_success_at: str
) -> tuple[int, str]:
    """Fetch CVEs modified since `last_success_at` and update EXISTING CVEs only.

    Returns `(updated, window_end)`: the number of already-present CVE nodes whose fields
    were updated, and the single instant captured before the fetch that was used as the
    request's `lastModEndDate`. The caller records `window_end` as the next poll's
    `last_success_at` so the next window starts exactly where this one ended — recording a
    fresh `now()` instead would leave a gap in which a CVE modified once is never re-polled.
    CVEs in the delta not already in the graph are ignored (FR-DC-23).
    """
    # One captured instant: the fetch-window end AND the next poll's window start.
    window_end = datetime.now(timezone.utc).isoformat()
    params = {
        "lastModStartDate": last_success_at,  # FR-DC-17
        "lastModEndDate": window_end,
    }
    response = http_client.get(_nvd_url(), params=params)
    body = handle_response(response, alert_fn=_alert)

    parsed = NvdNormalizer().parse(body)
    updated = 0
    with driver.session() as session:
        for record in parsed:
            outcome, cvss_changed = session.execute_write(
                _apply_cve_tx, record, allow_create=False
            )
            if outcome != "absent":
                updated += 1
            # Publish immediately after THIS record's transaction commits (still
            # post-commit -- a subscriber reading the node back sees the committed
            # cvss_score), rather than batching to the end of the loop. Batching would
            # mean a later record's execute_write raising (Neo4j blip, Lambda timeout)
            # discards the announcements for every already-committed record before it;
            # a retry re-derives `cvss_changed=False` for those (the score is already
            # updated), turning a transient failure into a PERMANENT missed
            # announcement (Task 1.2 fix round 1, finding I2).
            if cvss_changed:
                publish_node_write(
                    label="CVE", key={"cve_id": record.cve_id}, changed_fields=["cvss_score"]
                )

    return updated, window_end


_NVD_SOURCE_ID = "nvd"
_DEFAULT_LOOKBACK_HOURS = 24


def handler(event: dict, context: Any, *, driver=None, http_client: _HttpClient | None = None) -> dict:
    """Lambda entry point for the scheduled NVD delta poll (Standard/hourly tier).

    Reads `last_success_at` for the NVD source from the `PollingState` DynamoDB table
    (defaulting to a `_DEFAULT_LOOKBACK_HOURS` window on first run — larger than the
    hourly cadence, so a missed cycle self-heals rather than skipping CVEs), runs the
    delta poll, then records the poll outcome so the next run's window starts where this
    one ended. Seams (`driver`, `http_client`) are injectable for tests; production
    resolves the shared Neo4j driver and a real `httpx` client.
    """
    import os

    import boto3

    from src.collection.rss.dedup_state import record_poll_outcome

    close_client = False
    if http_client is None:
        import httpx

        http_client = httpx.Client()
        close_client = True
    if driver is None:
        from src.common.neo4j_driver import get_driver

        driver = get_driver()

    polling_table = boto3.resource("dynamodb").Table(os.environ["POLLING_STATE_TABLE_NAME"])
    item = polling_table.get_item(Key={"source_id": _NVD_SOURCE_ID}).get("Item", {})
    last_success_at = item.get("last_success_at") or (
        datetime.now(timezone.utc) - timedelta(hours=_DEFAULT_LOOKBACK_HOURS)
    ).isoformat()

    try:
        updated, window_end = poll_nvd_delta(driver, http_client, last_success_at)
        # Record the fetch-window end as the next poll's watermark, NOT a fresh now().
        record_poll_outcome(
            polling_table, _NVD_SOURCE_ID, success=True, success_at=window_end
        )
        return {"cves_updated": updated}
    except Exception:
        record_poll_outcome(polling_table, _NVD_SOURCE_ID, success=False)
        raise
    finally:
        if close_client:
            http_client.close()


def enrich_cve(driver, http_client: _HttpClient, cve_id: str) -> None:
    """On-demand: fetch one CVE from NVD by id and populate its fields (FR-DC-22).

    MERGEs the CVE, so it is safe whether or not the lazy-creation caller has already
    created the stub. Subject to the same CATEGORIZED_AS freshness guard as the delta.
    """
    params = {"cveId": cve_id}
    response = http_client.get(_nvd_url(), params=params)
    body = handle_response(response, alert_fn=_alert)

    parsed = NvdNormalizer().parse(body)
    cvss_changed = False
    with driver.session() as session:
        for record in parsed:
            if record.cve_id != cve_id:
                continue  # defensive: only the requested CVE
            _outcome, cvss_changed = session.execute_write(
                _apply_cve_tx, record, allow_create=True
            )

    # Publish only AFTER the transaction commits, so a subscriber reading the node back
    # sees the committed cvss_score.
    if cvss_changed:
        publish_node_write(label="CVE", key={"cve_id": cve_id}, changed_fields=["cvss_score"])
