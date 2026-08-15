"""MITRE ATT&CK STIX sync (L1 Task 11, Category C).

Daily version-gated full re-sync of MITRE ATT&CK's three domains (enterprise/mobile/ics)
from GitHub-hosted, versioned STIX 2.1 bundles (`mitre-attack/attack-stix-data`), per
`data-collection-layer/design.md` Part 5:

- Fetch each domain's small collection index and compare its version against the last
  ingested version (FR-DC-26). This always happens, for all three domains, regardless of
  whether anything changed -- it's the cheap check that decides whether to pay for the
  much larger bundle download.
- Only on a version bump: download that domain's full STIX bundle, parse it with
  `cti-python-stix2`, and MERGE every `attack-pattern`/`intrusion-set`/`malware`/`campaign`
  object plus their `uses`/`attributed-to` relationships (FR-DC-27). Each bundle is a
  complete snapshot, not a diff -- every object in it is written on every re-sync of that
  domain, which is what makes flag-flips (deprecated/revoked) and idempotent MERGE both
  correct for free.
- Deprecated/revoked objects are flagged via `SET`, never deleted, so their historical
  edges stay intact (FR-DC-28, NFR-DATA-03 "flag, don't delete").

**Contract seam:** `fetch_index_fn(domain: str) -> dict` and `fetch_bundle_fn(domain: str)
-> dict` are injected -- this module never makes a live GitHub call itself (nor does it
know GitHub's real repo layout; that's the caller's job to wire in production). Both
return already-JSON-decoded dicts.

  - `fetch_index_fn`'s return shape is a judgment call: MITRE's real, live "index of all
    domains" file (`attack-stix-data/index.json`) is one JSON document covering every
    domain, but each domain's own bundle also embeds an `x-mitre-collection` object
    carrying an `x_mitre_version` string. Neither shape is a good fit for a per-domain
    seam function called once per domain in a loop, so this module defines its own
    minimal contract instead of mirroring either verbatim: `fetch_index_fn(domain) ->
    {"version": "<version-string>", ...}`. Whoever wires the real GitHub fetch is free to
    adapt either upstream shape into this one.

**L3 reconciliation:** the brief's Step 4 describes hand-rolled "edge MERGEs,
endpoint-locked" -- that predates `src.common.graph`'s write library (L3, now built) and
is superseded by it here. `USES` and `ATTRIBUTED_TO` are both **assertion** edges per
`technical-specification.md` §3.2, written via
`src.common.graph.assertion_edges.upsert_authoritative_assertions_bulk` inside
`session.execute_write(...)` (never a bare session call -- that's how L3 avoids the
lost-update race a per-task review on the graph-writes branch already found and fixed).
`feed_source="mitre_attck"`, `credibility_score=1.0`: a judgment call, documented like
Task 9's abuse.ch scores -- MITRE ATT&CK is treated as maximally authoritative since it is
itself the primary, curated source for these object types (no third party to weigh it
against), consistent with Category C owning `Campaign` seed data outright. No
`publish_graph_write` call for these edges: the plan's Category C section describes no
`graph-writes` SNS announcement for ATT&CK's own edges (unlike Task 9's IOC/CVE
assertions, which feed L4 scoring off freshly-observed IOC activity) -- if that is wrong,
it should be corrected in the plan alongside the code, not silently added here.

**Batching (fixes a real production bug, 2026-08-15):** both node and edge writes go
through Neo4j one `UNWIND` round trip per batch (`attck_batch_size` config knob, default
500) instead of one `execute_write` per object/relationship. Confirmed live that the
per-relationship shape could not finish `enterprise-attack`'s ~25k relationships inside
the Lambda timeout -- three consecutive 600s runs made zero forward progress (see
CLAUDE.md Current State). Edges are grouped by (start_label, end_label, rel_type) before
batching, since labels/relationship types can't be parameterized in Cypher and must be
interpolated once per group rather than per row.

Node MERGEs (the four object types themselves) stay direct Neo4j `MERGE`/`SET`, batched
the same way: L3 ships only edge-writers, no node-writer, the same pattern Tasks 8/9
already established for `CVE`/`MalwareFamily`.

**`merge_key` / `technique_id` computation** (`technical-specification.md` §3.2, Cross-
Cutting Notes): `TTP` is keyed directly on `technique_id` (the object's own MITRE ID,
e.g. `T1566` or `T1566.001` for a sub-technique -- distinct natural keys per the design
doc). `ThreatActor`/`MalwareFamily`/`Campaign` are keyed on a derived `merge_key`: the
object's `mitre-attack` `external_references` entry's `external_id` if present, else a
normalized (`" ".join(name.split()).lower()` -- collapses internal whitespace runs to a
single space, then lowercases) form of the object's `name`. In practice every ATT&CK
object of these four types carries a `mitre-attack` external reference, so the name
fallback is a defensive edge case, not the common path.

FR-DC-26, FR-DC-27, FR-DC-28, FR-DC-01 (TTP, ThreatActor, MalwareFamily, Campaign).
"""

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Protocol

import stix2

from src.common.config import get_config
from src.common.graph.assertion_edges import upsert_authoritative_assertions_bulk
from src.common.graph.writer import _check_identifier

FEED_SOURCE = "mitre_attck"
CREDIBILITY_SCORE = 1.0

DOMAINS = ("enterprise-attack", "mobile-attack", "ics-attack")

_DEFAULT_BATCH_SIZE = 500

_USES_SOURCE_TYPES = {"intrusion-set", "malware", "campaign"}
_USES_TARGET_TYPES = {"malware", "attack-pattern"}


class _FetchIndexFn(Protocol):
    def __call__(self, domain: str) -> dict: ...


class _FetchBundleFn(Protocol):
    def __call__(self, domain: str) -> dict: ...


def _normalize_name(name: str) -> str:
    return " ".join(name.split()).lower()


def _mitre_external_ref(obj: Any) -> tuple[str | None, str | None]:
    """Return (external_id, url) from the object's `mitre-attack` external reference,
    or (None, None) if it has none (defensive -- see module docstring)."""
    for ref in getattr(obj, "external_references", None) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


def _merge_key(obj: Any) -> str:
    mitre_id, _ = _mitre_external_ref(obj)
    return mitre_id if mitre_id else _normalize_name(obj.name)


def _domain_short(domain: str) -> str:
    # "enterprise-attack" -> "enterprise", "mobile-attack" -> "mobile", "ics-attack" -> "ics"
    return domain.split("-")[0]


def _flags(obj: Any) -> dict:
    return {
        "is_deprecated": bool(getattr(obj, "x_mitre_deprecated", False)),
        "is_revoked": bool(getattr(obj, "revoked", False)),
        "revoked_by": getattr(obj, "x_mitre_revoked_by_id", None),
    }


def _ttp_properties(obj: Any, domain: str) -> tuple[str, dict]:
    technique_id, url = _mitre_external_ref(obj)
    if technique_id is None:
        # Defensive fallback only -- real ATT&CK attack-pattern objects always carry a
        # mitre-attack external reference. Documented in the module docstring.
        technique_id = _normalize_name(obj.name)
    tactics = [
        phase.get("phase_name")
        for phase in (getattr(obj, "kill_chain_phases", None) or [])
        if phase.get("kill_chain_name") == "mitre-attack"
    ]
    properties = {
        "name": obj.name,
        "sub_technique_id": technique_id if "." in technique_id else None,
        "tactic": tactics,
        "mitre_url": url,
        "domain": _domain_short(domain),
        **_flags(obj),
    }
    return technique_id, properties


def _threat_actor_properties(obj: Any) -> dict:
    mitre_id, _ = _mitre_external_ref(obj)
    return {
        "name": obj.name,
        "mitre_id": mitre_id,
        "aliases": list(getattr(obj, "aliases", None) or []),
        "description": getattr(obj, "description", None),
        **_flags(obj),
    }


def _malware_family_properties(obj: Any) -> dict:
    mitre_id, _ = _mitre_external_ref(obj)
    malware_types = list(getattr(obj, "malware_types", None) or [])
    return {
        "name": obj.name,
        "mitre_id": mitre_id,
        "aliases": list(getattr(obj, "aliases", None) or []),
        "malware_type": malware_types[0] if malware_types else None,
        "description": getattr(obj, "description", None),
        **_flags(obj),
    }


def _iso(value: Any) -> str | None:
    # Neo4j's Bolt packer has no encoding for stix2's own `STIXdatetime` type, so STIX
    # timestamp properties must cross the wire as plain ISO-8601 strings.
    return str(value) if value is not None else None


def _campaign_properties(obj: Any) -> dict:
    mitre_id, _ = _mitre_external_ref(obj)
    return {
        "name": obj.name,
        "mitre_id": mitre_id,
        "aliases": list(getattr(obj, "aliases", None) or []),
        "start_date": _iso(getattr(obj, "first_seen", None)),
        "end_date": _iso(getattr(obj, "last_seen", None)),
        "objective": getattr(obj, "objective", None),
        "description": getattr(obj, "description", None),
        **_flags(obj),
    }


def _bulk_merge_nodes_tx(tx, label: str, key_prop: str, rows: list[dict]) -> None:
    """rows: [{"key": <natural key value>, "props": {...}}]. One UNWIND round trip for
    the whole batch instead of one `execute_write` per node -- see module docstring."""
    _check_identifier(label, "label")
    _check_identifier(key_prop, "key property")
    tx.run(
        f"UNWIND $rows AS row MERGE (n:{label} {{{key_prop}: row.key}}) SET n += row.props",
        rows=rows,
    ).consume()


def _batches(rows: list, batch_size: int):
    for i in range(0, len(rows), batch_size):
        yield rows[i : i + batch_size]


def _sync_domain_bundle(
    driver, domain: str, bundle_raw: dict, *, now: datetime, batch_size: int | None = None
) -> None:
    if batch_size is None:
        batch_size = int(get_config("attck_batch_size", default=str(_DEFAULT_BATCH_SIZE)))

    parsed = stix2.parse(bundle_raw, allow_custom=True)

    # Maps a STIX object id (e.g. "intrusion-set--...") to the (label, key_prop,
    # key_value) a relationship endpoint resolves to, so the second (edge) pass never
    # has to re-walk or re-parse the node objects.
    id_to_endpoint: dict[str, tuple[str, str, str]] = {}
    # Grouped by (label, key_prop): labels/property names can't be parameterized in
    # Cypher, so each group is interpolated once and its rows batched via UNWIND.
    node_groups: dict[tuple[str, str], list[dict]] = {}
    relationships: list[Any] = []

    for obj in parsed.objects:
        # stix2 returns unrecognised types (ATT&CK's own x-mitre-tactic, x-mitre-matrix,
        # x-mitre-data-source, ...) as plain dicts rather than parsed objects, so this
        # cannot be `obj.type`. Everything acted on below is a standard STIX type and
        # therefore always a real object; the dicts fall through and are skipped.
        obj_type = obj["type"] if isinstance(obj, dict) else obj.type
        if obj_type == "attack-pattern":
            technique_id, properties = _ttp_properties(obj, domain)
            id_to_endpoint[obj.id] = ("TTP", "technique_id", technique_id)
            node_groups.setdefault(("TTP", "technique_id"), []).append(
                {"key": technique_id, "props": properties}
            )
        elif obj_type == "intrusion-set":
            merge_key = _merge_key(obj)
            id_to_endpoint[obj.id] = ("ThreatActor", "merge_key", merge_key)
            node_groups.setdefault(("ThreatActor", "merge_key"), []).append(
                {"key": merge_key, "props": _threat_actor_properties(obj)}
            )
        elif obj_type == "malware":
            merge_key = _merge_key(obj)
            id_to_endpoint[obj.id] = ("MalwareFamily", "merge_key", merge_key)
            node_groups.setdefault(("MalwareFamily", "merge_key"), []).append(
                {"key": merge_key, "props": _malware_family_properties(obj)}
            )
        elif obj_type == "campaign":
            merge_key = _merge_key(obj)
            id_to_endpoint[obj.id] = ("Campaign", "merge_key", merge_key)
            node_groups.setdefault(("Campaign", "merge_key"), []).append(
                {"key": merge_key, "props": _campaign_properties(obj)}
            )
        elif obj_type == "relationship":
            relationships.append(obj)

    with driver.session() as session:
        for (label, key_prop), rows in node_groups.items():
            for chunk in _batches(rows, batch_size):
                session.execute_write(_bulk_merge_nodes_tx, label, key_prop, chunk)

    # Grouped by (start_label, end_label, rel_type) for the same interpolation reason.
    edge_groups: dict[tuple[str, str, str, str, str], list[dict]] = {}
    for rel in relationships:
        if rel.relationship_type == "uses":
            rel_type = "USES"
        elif rel.relationship_type == "attributed-to":
            rel_type = "ATTRIBUTED_TO"
        else:
            continue  # out of scope for this task -- only uses/attributed-to are synced

        start = id_to_endpoint.get(rel.source_ref)
        end = id_to_endpoint.get(rel.target_ref)
        if start is None or end is None:
            # Endpoint outside this bundle's four object types (or a relationship this
            # sync doesn't model) -- nothing to link.
            continue
        start_label, start_key_prop, start_key = start
        end_label, end_key_prop, end_key = end
        group = (start_label, start_key_prop, end_label, end_key_prop, rel_type)
        edge_groups.setdefault(group, []).append({"start_key": start_key, "end_key": end_key})

    with driver.session() as session:
        for (start_label, start_key_prop, end_label, end_key_prop, rel_type), rows in edge_groups.items():
            for chunk in _batches(rows, batch_size):
                session.execute_write(
                    lambda tx, c=chunk, sl=start_label, skp=start_key_prop, el=end_label,
                    ekp=end_key_prop, rt=rel_type: upsert_authoritative_assertions_bulk(
                        tx, start_label=sl, start_key_prop=skp, end_label=el, end_key_prop=ekp,
                        rel_type=rt, rows=c, feed_source=FEED_SOURCE,
                        credibility_score=CREDIBILITY_SCORE, now=now,
                    )
                )


def sync_attck(
    driver,
    fetch_index_fn: _FetchIndexFn,
    fetch_bundle_fn: _FetchBundleFn,
    last_ingested_versions: dict[str, str],
    on_domain_synced: Callable[[str, str], None] | None = None,
) -> dict[str, str]:
    """Check each of the three ATT&CK domains' collection index (FR-DC-26, always, for
    all three) and, only where the version has bumped since `last_ingested_versions`,
    download and fully re-sync that domain's bundle (FR-DC-27/28).

    Returns a dict of only the domains actually (re-)ingested this run, mapping domain ->
    the new version now ingested -- the caller persists this to seed the next run's
    `last_ingested_versions`.

    `on_domain_synced(domain, version)` is called as soon as each domain finishes, so
    the caller can bank that domain's watermark immediately. Persisting only from the
    return value loses every completed domain when a later one fails: a run that hits
    the Lambda timeout partway through banks nothing, and re-syncs already-completed
    domains from scratch on every subsequent run without ever converging. The re-sync
    itself is harmless (all writes are MERGEs) -- never finishing is the bug.
    """
    now = datetime.now(timezone.utc)
    newly_ingested: dict[str, str] = {}
    for domain in DOMAINS:
        index = fetch_index_fn(domain)
        version = index["version"]
        if last_ingested_versions.get(domain) == version:
            continue
        bundle_raw = fetch_bundle_fn(domain)
        _sync_domain_bundle(driver, domain, bundle_raw, now=now)
        newly_ingested[domain] = version
        if on_domain_synced is not None:
            on_domain_synced(domain, version)
    return newly_ingested


_ATTCK_SOURCE_ID = "mitre_attck"
_GITHUB_RAW_BASE = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
)

# Maps this module's domain keys to the collection `name` MITRE uses in `index.json`.
_DOMAIN_COLLECTION_NAME = {
    "enterprise-attack": "Enterprise ATT&CK",
    "mobile-attack": "Mobile ATT&CK",
    "ics-attack": "ICS ATT&CK",
}


def _version_tuple(version: str) -> tuple:
    parts: list[int] = []
    for piece in version.split("."):
        try:
            parts.append(int(piece))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _make_github_fetchers(http_client):
    """Build the `(fetch_index_fn, fetch_bundle_fn)` pair against MITRE's GitHub-hosted
    `attack-stix-data` repo, adapting its real layout into this module's per-domain
    contract (`fetch_index_fn(domain) -> {"version": ...}`; `fetch_bundle_fn(domain) ->
    <parsed bundle dict>`). The single `index.json` (one document covering every domain)
    is fetched once and cached across the three per-domain index calls.
    """
    cache: dict = {}

    def _index() -> dict:
        if "index" not in cache:
            resp = http_client.get(f"{_GITHUB_RAW_BASE}/index.json", timeout=60.0)
            resp.raise_for_status()
            cache["index"] = resp.json()
        return cache["index"]

    def fetch_index_fn(domain: str) -> dict:
        collection_name = _DOMAIN_COLLECTION_NAME.get(domain)
        for collection in _index().get("collections", []):
            if collection.get("name") == collection_name:
                versions = [v.get("version") for v in collection.get("versions", []) if v.get("version")]
                if versions:
                    return {"version": max(versions, key=_version_tuple)}
        # No matching collection/version -> a version string that never equals a stored
        # one would force a re-sync; instead return an empty sentinel the caller treats as
        # "unknown" (it will still attempt a bundle fetch and MERGE idempotently).
        return {"version": ""}

    def fetch_bundle_fn(domain: str) -> dict:
        resp = http_client.get(f"{_GITHUB_RAW_BASE}/{domain}/{domain}.json", timeout=120.0)
        resp.raise_for_status()
        return resp.json()

    return fetch_index_fn, fetch_bundle_fn


def handler(
    event: Any = None,
    context: Any = None,
    *,
    driver=None,
    fetch_index_fn: _FetchIndexFn | None = None,
    fetch_bundle_fn: _FetchBundleFn | None = None,
) -> dict:
    """Lambda entry point for the daily ATT&CK sync (Category C).

    Reads the per-domain `last_ingested_versions` map from the `PollingState` DynamoDB
    table (keyed `source_id="mitre_attck"`), runs the version-gated re-sync, and persists
    the merged versions back so the next run only downloads a domain whose version bumped
    (FR-DC-26). Seams are injectable for tests; production builds the GitHub fetchers and
    resolves the shared Neo4j driver.
    """
    import os

    import boto3

    close_client = False
    http_client = None
    if fetch_index_fn is None or fetch_bundle_fn is None:
        import httpx

        http_client = httpx.Client(follow_redirects=True)
        close_client = True
        default_index_fn, default_bundle_fn = _make_github_fetchers(http_client)
        fetch_index_fn = fetch_index_fn or default_index_fn
        fetch_bundle_fn = fetch_bundle_fn or default_bundle_fn
    if driver is None:
        from src.common.neo4j_driver import get_driver

        driver = get_driver()

    polling_table = boto3.resource("dynamodb").Table(os.environ["POLLING_STATE_TABLE_NAME"])
    item = polling_table.get_item(Key={"source_id": _ATTCK_SOURCE_ID}).get("Item", {})
    last_ingested_versions = dict(item.get("last_ingested_versions", {}))

    def _persist_domain(domain: str, version: str) -> None:
        """Bank each domain's watermark the moment it lands, not after all three.

        Syncing all three domains does not fit in the Lambda's timeout, so persisting
        only at the end meant a timeout during a later domain discarded an earlier
        domain's completed work and the job could never converge. Per-domain
        persistence turns one impossible run into several that each make durable
        progress.
        """
        last_ingested_versions[domain] = version
        polling_table.update_item(
            Key={"source_id": _ATTCK_SOURCE_ID},
            UpdateExpression="SET last_ingested_versions = :v",
            ExpressionAttributeValues={":v": last_ingested_versions},
        )

    try:
        newly_ingested = sync_attck(
            driver, fetch_index_fn, fetch_bundle_fn, last_ingested_versions,
            on_domain_synced=_persist_domain,
        )
    finally:
        if close_client and http_client is not None:
            http_client.close()

    return {"domains_ingested": newly_ingested}
