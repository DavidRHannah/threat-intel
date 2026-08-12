"""What is publishable (FR-IO-07, interoperability-layer/design.md Part 5).

Layer 4's scores do double duty here: they rank internally AND gate what leaves the
platform. A `:Provisional` node (unreconciled NLP-discovered entity) or anything flagged
`prune_candidate` by L4's sweep is never exported, regardless of its current confidence --
an unverified name must not propagate as a named actor, and a candidate for deletion must
not be handed to an external consumer moments before it disappears.
"""


def passes_export_gate(label: str, props: dict, *, floor: float) -> bool:
    if props.get("is_provisional"):
        return False
    if props.get("prune_candidate"):
        return False
    return float(props.get("confidence", 0.0)) >= floor


def filter_object_refs(candidate_ids: list[str], exported_ids: set[str]) -> list[str]:
    """A `report`'s `object_refs` must reference only exported objects (FR-IO-07) -- a
    gated-out reference is OMITTED, never left dangling for a consumer to chase."""
    return [cid for cid in candidate_ids if cid in exported_ids]
