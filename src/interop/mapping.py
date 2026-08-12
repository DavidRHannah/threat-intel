"""Graph node/edge -> STIX 2.1 SDO/SRO (interoperability-layer/design.md Part 3).

Every function here is PURE: takes already-fetched graph properties, returns a stix2
object. No Neo4j access -- src/interop/queries.py owns fetching, this module owns
translation, matching src/scoring's split between Cypher and formulas.
"""

import stix2

from src.interop.stix_ids import (
    NATURAL_KEY_PROP_BY_LABEL,
    relationship_stix_id,
    stix_id,
)
from src.interop.tlp import TLP_CLEAR

# design.md Part 3's edge -> relationship_type table.
_REL_TYPE_MAP: dict[str, str] = {
    "EXPLOITED_BY": "exploits",  # direction flipped to STIX convention below
    "USES": "uses",
    "ATTRIBUTED_TO": "attributed-to",
    "INDICATES": "indicates",
    "HAS_SAMPLE": "indicates",
    "COMMUNICATES_WITH": "related-to",
    "ASSOCIATED_WITH": "related-to",
}

# design.md Part 3's IOC pattern mapping, covering all 6 ioc_type values known to be
# live-ingested per src/collection/rest/{otx,abusech}.py's _TYPE_MAP / _HASH_TYPES
# (ip, domain, url, sha256_hash, sha1_hash, md5_hash). `ip:port` (ThreatFox) has no
# entry here -- it has no single STIX SCO representation and is handled as a special
# case in `_ioc_to_indicator` below.
_IOC_PATTERN_BY_TYPE: dict[str, str] = {
    "ip": "[ipv4-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "sha256_hash": "[file:hashes.'SHA-256' = '{value}']",
    "sha1_hash": "[file:hashes.'SHA-1' = '{value}']",
    "md5_hash": "[file:hashes.'MD5' = '{value}']",
}


def _confidence100(props: dict) -> int:
    """Our 0-1 confidence -> STIX's 0-100 (FR-IO-05)."""
    return round(float(props.get("confidence", 0.0)) * 100)


def _dt(value):
    """Pass a datetime straight through to stix2's DateTimeProperty; return None for
    an absent value (stix2 auto-fills `created` with now() when None -- everywhere
    else, None is the field's own documented "not provided" state, e.g. Indicator's
    optional `valid_from` fallback below).

    Deliberately NOT `.isoformat()`'d: verified directly against stix2==3.0.1 that its
    DateTimeProperty only accepts a datetime/date object or a strict `%Y-%m-%dT%H:%M:%SZ`
    string -- `.isoformat()`'s `+00:00` offset suffix raises InvalidValueError. The
    driver itself returns `neo4j.time.DateTime` (not a native `datetime`) for temporal
    properties -- `src/interop/queries.py`'s `_normalize_props` converts every
    node/edge property dict this module ever sees to native `datetime` before it
    reaches here, so by the time a value arrives at `_dt` it is always already native;
    a value that is already a plain str (defensive: some upstream writer stored one)
    is returned as-is and left to stix2's own parser."""
    if value is None:
        return None
    return value


def _node_id(label: str, props: dict, *, namespace: str) -> str:
    key_prop = NATURAL_KEY_PROP_BY_LABEL[label]
    return stix_id(label, props[key_prop], namespace=namespace)


def _cve_to_vulnerability(props: dict, *, namespace: str) -> stix2.v21.Vulnerability:
    external_refs = [{"source_name": "nvd", "external_id": props["cve_id"]}]
    return stix2.v21.Vulnerability(
        id=_node_id("CVE", props, namespace=namespace),
        name=props["cve_id"],
        description=props.get("description", ""),
        confidence=_confidence100(props),
        created=_dt(props.get("first_seen")),
        modified=_dt(props.get("last_updated")),
        external_references=external_refs,
        object_marking_refs=[TLP_CLEAR.id],
        allow_custom=True,
    )


def _actor_to_intrusion_set(props: dict, *, namespace: str) -> stix2.v21.IntrusionSet:
    return stix2.v21.IntrusionSet(
        id=_node_id("ThreatActor", props, namespace=namespace),
        name=props.get("name") or props["merge_key"],
        aliases=props.get("aliases") or [],
        confidence=_confidence100(props),
        created=_dt(props.get("first_seen")),
        modified=_dt(props.get("last_updated")),
        object_marking_refs=[TLP_CLEAR.id],
    )


def _malware_to_malware(props: dict, *, namespace: str) -> stix2.v21.Malware:
    return stix2.v21.Malware(
        id=_node_id("MalwareFamily", props, namespace=namespace),
        name=props.get("name") or props["merge_key"],
        is_family=True,
        aliases=props.get("aliases") or [],
        confidence=_confidence100(props),
        created=_dt(props.get("first_seen")),
        modified=_dt(props.get("last_updated")),
        object_marking_refs=[TLP_CLEAR.id],
    )


def _campaign_to_campaign(props: dict, *, namespace: str) -> stix2.v21.Campaign:
    return stix2.v21.Campaign(
        id=_node_id("Campaign", props, namespace=namespace),
        name=props.get("name") or props["merge_key"],
        aliases=props.get("aliases") or [],
        confidence=_confidence100(props),
        created=_dt(props.get("first_seen")),
        modified=_dt(props.get("last_updated")),
        object_marking_refs=[TLP_CLEAR.id],
    )


def _ttp_to_attack_pattern(props: dict, *, namespace: str) -> stix2.v21.AttackPattern:
    technique_id = props["technique_id"]
    return stix2.v21.AttackPattern(
        id=_node_id("TTP", props, namespace=namespace),
        name=props.get("name") or technique_id,
        external_references=[
            {
                "source_name": "mitre-attack",
                "external_id": technique_id,
                "url": props.get("mitre_url"),
            }
        ],
        created=_dt(props.get("first_seen")),
        modified=_dt(props.get("last_updated")),
        object_marking_refs=[TLP_CLEAR.id],
    )


def _ioc_to_indicator(props: dict, *, namespace: str) -> stix2.v21.Indicator:
    ioc_type = props["ioc_type"]
    value = props["value"]
    if ioc_type == "ip:port":
        # STIX 2.1 core has no single SCO for a combined ip:port scalar; a full
        # network-traffic object (src_ref/dst_port) is deferred. Known lossy
        # simplification: export just the IP, drop the port.
        value = value.rsplit(":", 1)[0]
        ioc_type = "ip"
    template = _IOC_PATTERN_BY_TYPE.get(ioc_type)
    if template is None:
        raise ValueError(f"no STIX pattern mapping for ioc_type={ioc_type!r}")
    pattern = template.format(value=value)
    return stix2.v21.Indicator(
        id=_node_id("IOC", props, namespace=namespace),
        pattern=pattern,
        pattern_type="stix",
        confidence=_confidence100(props),
        valid_from=_dt(props.get("first_seen")) or _dt(props.get("last_updated")),
        created=_dt(props.get("first_seen")),
        modified=_dt(props.get("last_updated")),
        object_marking_refs=[TLP_CLEAR.id],
    )


def _article_to_report(
    props: dict, *, namespace: str, object_refs: list[str], created_by_ref: str | None = None,
) -> stix2.v21.Report:
    """`object_refs` must be non-empty and must reference only SDOs/SCOs -- STIX forbids
    an empty list, and a marking-definition id is not a legal member of it. This function
    does not paper over an empty list with a fallback ref: the caller (`objects_handler`)
    is responsible for skipping report generation entirely when `_mentioned_stix_ids`
    (src/interop/taxii_handler.py, gated on the mentioned node's persisted `exported`
    flag) returns nothing, so this always receives a non-empty, already-gated list."""
    return stix2.v21.Report(
        id=_node_id("Article", props, namespace=namespace),
        name=props.get("title") or props["source_guid_key"],
        description=props.get("summary", ""),
        published=_dt(props.get("published_at")) or _dt(props.get("fetched_at")),
        object_refs=object_refs,
        created_by_ref=created_by_ref,
        object_marking_refs=[TLP_CLEAR.id],
    )


def _source_to_identity(props: dict, *, namespace: str) -> stix2.v21.Identity:
    return stix2.v21.Identity(
        id=_node_id("Source", props, namespace=namespace),
        name=props.get("name") or props["url"],
        identity_class="organization",
        object_marking_refs=[TLP_CLEAR.id],
    )


_NODE_MAPPERS = {
    "CVE": _cve_to_vulnerability,
    "ThreatActor": _actor_to_intrusion_set,
    "MalwareFamily": _malware_to_malware,
    "Campaign": _campaign_to_campaign,
    "TTP": _ttp_to_attack_pattern,
    "IOC": _ioc_to_indicator,
    "Source": _source_to_identity,
}


def node_to_stix(label: str, props: dict, *, namespace: str, **kwargs):
    """`Article` is intentionally NOT in `_NODE_MAPPERS`: it needs `object_refs`
    (Task 0.5's gating owns computing that list), so callers use `_article_to_report`
    directly via `report_to_stix` below rather than this generic dispatcher."""
    mapper = _NODE_MAPPERS[label]
    return mapper(props, namespace=namespace)


def report_to_stix(props: dict, *, namespace: str, object_refs: list[str]) -> stix2.v21.Report:
    return _article_to_report(props, namespace=namespace, object_refs=object_refs)


def edge_to_stix(
    rel_type: str,
    start_label: str,
    start_props: dict,
    end_label: str,
    end_props: dict,
    edge_props: dict,
    *,
    namespace: str,
) -> stix2.v21.Relationship:
    """`start_label`/`start_props` and `end_label`/`end_props` are the graph's own
    direction. EXPLOITED_BY is CVE->exploiter in the graph but STIX's convention is
    exploiter->vulnerability (design.md Part 3), so that one case swaps source/target;
    every other mapped edge keeps the graph's direction."""
    relationship_type = _REL_TYPE_MAP[rel_type]
    start_id = _node_id(start_label, start_props, namespace=namespace)
    end_id = _node_id(end_label, end_props, namespace=namespace)
    start_key_val = start_props[NATURAL_KEY_PROP_BY_LABEL[start_label]]
    end_key_val = end_props[NATURAL_KEY_PROP_BY_LABEL[end_label]]

    if rel_type == "EXPLOITED_BY":
        source_ref, target_ref = end_id, start_id
        rel_start_key, rel_end_key = end_key_val, start_key_val
        rel_start_label, rel_end_label = end_label, start_label
    else:
        source_ref, target_ref = start_id, end_id
        rel_start_key, rel_end_key = start_key_val, end_key_val
        rel_start_label, rel_end_label = start_label, end_label

    rel_id = relationship_stix_id(
        rel_type, rel_start_label, rel_start_key, rel_end_label, rel_end_key,
        namespace=namespace,
    )
    return stix2.v21.Relationship(
        id=rel_id,
        relationship_type=relationship_type,
        source_ref=source_ref,
        target_ref=target_ref,
        confidence=_confidence100(edge_props),
        created=_dt(edge_props.get("first_observed")),
        modified=_dt(edge_props.get("last_updated")),
        object_marking_refs=[TLP_CLEAR.id],
    )
