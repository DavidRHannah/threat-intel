"""Label/key metadata shared across the scoring modules."""

from src.common.graph.writer import _check_identifier

# The MERGE key property per label (technical-specification.md §3.1).
KEY_PROP_BY_LABEL: dict[str, str] = {
    "CVE": "cve_id",
    "IOC": "value_type_key",
    "ThreatActor": "merge_key",
    "MalwareFamily": "merge_key",
    "Campaign": "merge_key",
}

# Labels carrying relevance_score (technical-specification.md §3.1). TTP/CWE/Source/
# Article are deliberately absent: none is a user-surfaced threat entity.
SCORED_LABELS: tuple[str, ...] = (
    "CVE",
    "ThreatActor",
    "MalwareFamily",
    "Campaign",
    "IOC",
)


def resolve_key_prop(label: str) -> str | None:
    """Validate `label` and return its validated key property, or None if unscored.

    Every query builder in this package interpolates BOTH values into Cypher, so BOTH
    go through _check_identifier -- no exceptions, per the Global Constraints. The map
    is a module constant today, but the constraint's whole value is that it needs no
    case-by-case analysis of which values happen to be trusted.
    """
    _check_identifier(label, "label")
    key_prop = KEY_PROP_BY_LABEL.get(label)
    if key_prop is None:
        return None
    return _check_identifier(key_prop, "key property")
