"""CISA KEV (Known Exploited Vulnerabilities) normalizer (L1 Task 9).

CISA KEV publishes a single flat JSON catalog (no auth, no pagination — spec §6).
Each entry's `cveID` is CISA's *implicit exploited-in-wild signal*: this is a plain CVE
node property (`exploited_in_wild = true`), never an edge — there is no other endpoint
for it to connect to, and the technical-specification.md §3.2 edge table has no
CVE-property-shaped edge type. This reads the brief's Step 2 bullet the same way it is
written ("MERGE CVE {exploited_in_wild: true} (lazy stub if absent...)").

Whichever CVE ids the graph hasn't seen yet get a lazy stub `MERGE`d (FR-DC-01) and then
on-demand NVD enrichment is *triggered* (FR-DC-22) via `src.collection.rest.nvd.enrich_cve`
— per that module's own docstring, which names CISA KEV as exactly this kind of caller.
Already-present CVEs are left to the NVD delta poll's own cadence; re-enriching them here
on every KEV cycle would just fight the CATEGORIZED_AS freshness guard for no benefit.

FR-DC-22, FR-DC-01 (CVE stub).
"""

from dataclasses import dataclass, field
from typing import Any, Protocol

from src.collection.rest.http_errors import handle_response
from src.collection.rest.normalizer import NodeUpsert
from src.collection.rest.nvd import enrich_cve
from src.common.config import get_config

SOURCE_ID = "cisa_kev"


class _HttpClient(Protocol):
    def get(self, url: str, params: dict | None = None) -> Any: ...


@dataclass
class ParsedKevEntry:
    cve_id: str
    properties: dict[str, Any] = field(default_factory=dict)


def _kev_url() -> str:
    return get_config(
        "cisa_kev_catalog_url",
        default=(
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json"
        ),
    )


def _kev_schema_valid(body: Any) -> bool:
    return isinstance(body, dict) and isinstance(body.get("vulnerabilities"), list)


class CisaKevNormalizer:
    """Maps a CISA KEV catalog response into parsed entries / NodeUpserts.

    Implements the `SourceNormalizer` protocol via `normalize`.
    """

    def parse(self, raw_response: dict) -> list[ParsedKevEntry]:
        out: list[ParsedKevEntry] = []
        for item in raw_response.get("vulnerabilities", []):
            cve_id = item.get("cveID")
            if not cve_id:
                continue
            raw_props = {
                "exploited_in_wild": True,
                "kev_vendor_project": item.get("vendorProject"),
                "kev_product": item.get("product"),
                "kev_vulnerability_name": item.get("vulnerabilityName"),
                "kev_date_added": item.get("dateAdded"),
                "kev_required_action": item.get("requiredAction"),
                "kev_due_date": item.get("dueDate"),
                "kev_known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
            }
            props = {k: v for k, v in raw_props.items() if v is not None}
            out.append(ParsedKevEntry(cve_id=cve_id, properties=props))
        return out

    def normalize(self, raw_response: dict) -> list[NodeUpsert]:
        return [
            NodeUpsert(label="CVE", natural_key={"cve_id": p.cve_id}, properties=p.properties)
            for p in self.parse(raw_response)
        ]


def _apply_kev_entry_tx(tx, entry: ParsedKevEntry) -> str:
    """Lazy-MERGE the CVE stub and SET the KEV fields, atomically. Returns 'created' (no
    prior CVE node existed -> caller must trigger on-demand NVD enrichment, FR-DC-22) or
    'existing' (already in the graph -> leave enrichment to NVD's own delta cadence)."""
    row = tx.run("MATCH (c:CVE {cve_id:$id}) RETURN c", id=entry.cve_id).single()
    outcome = "existing" if row is not None else "created"
    tx.run("MERGE (c:CVE {cve_id:$id})", id=entry.cve_id).consume()
    if entry.properties:
        tx.run(
            "MATCH (c:CVE {cve_id:$id}) SET c += $props", id=entry.cve_id, props=entry.properties
        ).consume()
    return outcome


def _alert(_response: Any) -> None:
    # CISA KEV needs no credential (spec §6); a 401/403 here would signal a CDN/WAF
    # misconfiguration rather than an expired key. Nothing else to publish -- the raised
    # NoRetryError already surfaces the failure to the caller.
    pass


def process_cisa_kev(driver, http_client: _HttpClient, nvd_http_client: _HttpClient) -> int:
    """Fetch the KEV catalog, MERGE/lazy-create each referenced CVE, set
    `exploited_in_wild` + the KEV fields, and trigger on-demand NVD enrichment (FR-DC-22)
    for every CVE the graph had not already seen. Returns the count of newly-created
    (and therefore enriched) CVE stubs.
    """
    response = http_client.get(_kev_url())
    body = handle_response(response, alert_fn=_alert, schema_validator=_kev_schema_valid)

    entries = CisaKevNormalizer().parse(body)
    newly_created: list[str] = []
    with driver.session() as session:
        for entry in entries:
            outcome = session.execute_write(_apply_kev_entry_tx, entry)
            if outcome == "created":
                newly_created.append(entry.cve_id)

    # enrich_cve opens its own session/transaction -- called after the outer `with`
    # block closes rather than nested inside it.
    for cve_id in newly_created:
        enrich_cve(driver, nvd_http_client, cve_id)

    return len(newly_created)
