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
`src.common.graph.assertion_edges.upsert_authoritative_assertion` inside
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

Node MERGEs (the four object types themselves) stay direct Neo4j `MERGE`/`SET`: L3 ships
only edge-writers, no node-writer, the same pattern Tasks 8/9 already established for
`CVE`/`MalwareFamily`.

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

from datetime import datetime, timezone
from typing import Any, Protocol

import stix2

from src.common.graph.assertion_edges import upsert_authoritative_assertion

FEED_SOURCE = "mitre_attck"
CREDIBILITY_SCORE = 1.0

DOMAINS = ("enterprise-attack", "mobile-attack", "ics-attack")

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


def _merge_ttp_tx(tx, technique_id: str, properties: dict) -> None:
    tx.run(
        "MERGE (t:TTP {technique_id: $key}) SET t += $props",
        key=technique_id, props=properties,
    ).consume()


def _merge_threat_actor_tx(tx, merge_key: str, properties: dict) -> None:
    tx.run(
        "MERGE (a:ThreatActor {merge_key: $key}) SET a += $props",
        key=merge_key, props=properties,
    ).consume()


def _merge_malware_family_tx(tx, merge_key: str, properties: dict) -> None:
    tx.run(
        "MERGE (m:MalwareFamily {merge_key: $key}) SET m += $props",
        key=merge_key, props=properties,
    ).consume()


def _merge_campaign_tx(tx, merge_key: str, properties: dict) -> None:
    tx.run(
        "MERGE (c:Campaign {merge_key: $key}) SET c += $props",
        key=merge_key, props=properties,
    ).consume()


def _write_edge_tx(tx, *, start_label, start_key, end_label, end_key, rel_type, now) -> str:
    return upsert_authoritative_assertion(
        tx,
        start_label=start_label,
        start_key=start_key,
        end_label=end_label,
        end_key=end_key,
        rel_type=rel_type,
        feed_source=FEED_SOURCE,
        credibility_score=CREDIBILITY_SCORE,
        now=now,
    )


def _sync_domain_bundle(driver, domain: str, bundle_raw: dict, *, now: datetime) -> None:
    parsed = stix2.parse(bundle_raw, allow_custom=True)

    # Maps a STIX object id (e.g. "intrusion-set--...") to the (label, natural-key dict)
    # a relationship endpoint resolves to, so the second (edge) pass never has to
    # re-walk or re-parse the node objects.
    id_to_endpoint: dict[str, tuple[str, dict]] = {}
    node_writes: list[tuple[Any, str, dict]] = []  # (tx_fn, key, properties)
    relationships: list[Any] = []

    for obj in parsed.objects:
        if obj.type == "attack-pattern":
            technique_id, properties = _ttp_properties(obj, domain)
            id_to_endpoint[obj.id] = ("TTP", {"technique_id": technique_id})
            node_writes.append((_merge_ttp_tx, technique_id, properties))
        elif obj.type == "intrusion-set":
            merge_key = _merge_key(obj)
            id_to_endpoint[obj.id] = ("ThreatActor", {"merge_key": merge_key})
            node_writes.append((_merge_threat_actor_tx, merge_key, _threat_actor_properties(obj)))
        elif obj.type == "malware":
            merge_key = _merge_key(obj)
            id_to_endpoint[obj.id] = ("MalwareFamily", {"merge_key": merge_key})
            node_writes.append((_merge_malware_family_tx, merge_key, _malware_family_properties(obj)))
        elif obj.type == "campaign":
            merge_key = _merge_key(obj)
            id_to_endpoint[obj.id] = ("Campaign", {"merge_key": merge_key})
            node_writes.append((_merge_campaign_tx, merge_key, _campaign_properties(obj)))
        elif obj.type == "relationship":
            relationships.append(obj)

    with driver.session() as session:
        for tx_fn, key, properties in node_writes:
            session.execute_write(tx_fn, key, properties)

    with driver.session() as session:
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
            start_label, start_key = start
            end_label, end_key = end
            session.execute_write(
                _write_edge_tx,
                start_label=start_label,
                start_key=start_key,
                end_label=end_label,
                end_key=end_key,
                rel_type=rel_type,
                now=now,
            )


def sync_attck(
    driver,
    fetch_index_fn: _FetchIndexFn,
    fetch_bundle_fn: _FetchBundleFn,
    last_ingested_versions: dict[str, str],
) -> dict[str, str]:
    """Check each of the three ATT&CK domains' collection index (FR-DC-26, always, for
    all three) and, only where the version has bumped since `last_ingested_versions`,
    download and fully re-sync that domain's bundle (FR-DC-27/28).

    Returns a dict of only the domains actually (re-)ingested this run, mapping domain ->
    the new version now ingested -- the caller persists this to seed the next run's
    `last_ingested_versions`.
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
    return newly_ingested
