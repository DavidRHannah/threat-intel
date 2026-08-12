"""Deterministic STIX 2.1 object ids (FR-IO-03, interoperability-layer/design.md Part 4).

`id = <stix-type>--UUIDv5(fixed namespace, "<label>:<natural-key-value>")`. Same node,
polled twice, must yield the identical id -- that is what lets a TAXII consumer UPDATE an
object instead of duplicating it. No stored mapping: the id is always re-derived.

The label is folded into the UUIDv5 input, not just the natural key value, because
`merge_key` (ThreatActor/MalwareFamily/Campaign) is a lowercased normalized NAME whose
UNIQUE constraint is PER-LABEL (src/scoring/_shared.py has the same note) -- a
ThreatActor and a MalwareFamily can both legitimately answer to 'lazarus'.
"""

import uuid

NATURAL_KEY_PROP_BY_LABEL: dict[str, str] = {
    "CVE": "cve_id",
    "TTP": "technique_id",
    "IOC": "value_type_key",
    "ThreatActor": "merge_key",
    "MalwareFamily": "merge_key",
    "Campaign": "merge_key",
    "Article": "source_guid_key",
    "Source": "url",
}

STIX_TYPE_BY_LABEL: dict[str, str] = {
    "CVE": "vulnerability",
    "ThreatActor": "intrusion-set",
    "MalwareFamily": "malware",
    "TTP": "attack-pattern",
    "Campaign": "campaign",
    "IOC": "indicator",
    "Article": "report",
    "Source": "identity",
}

# Exportable node labels this layer ever produces SDOs for (CWE has no core SDO --
# design.md Part 3 -- and is folded into vulnerability.external_references instead).
EXPORTABLE_NODE_LABELS: tuple[str, ...] = tuple(STIX_TYPE_BY_LABEL.keys())


def stix_id(label: str, key_value: str, *, namespace: str) -> str:
    stix_type = STIX_TYPE_BY_LABEL[label]
    ns_uuid = uuid.UUID(namespace)
    derived = uuid.uuid5(ns_uuid, f"{label}:{key_value}")
    return f"{stix_type}--{derived}"


def relationship_stix_id(
    rel_type: str, start_label: str, start_key: str, end_label: str, end_key: str,
    *, namespace: str,
) -> str:
    """SROs have no natural key of their own in the graph -- identity = (start, type,
    end), same as the graph's own assertion-edge identity (technical-specification.md
    sec 3.2). Deterministic the same way: hash the triple."""
    ns_uuid = uuid.UUID(namespace)
    derived = uuid.uuid5(
        ns_uuid, f"relationship:{start_label}:{start_key}:{rel_type}:{end_label}:{end_key}"
    )
    return f"relationship--{derived}"
