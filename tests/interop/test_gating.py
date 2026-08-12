from src.interop.gating import filter_object_refs, passes_export_gate


def test_provisional_node_never_passes():
    props = {"confidence": 0.9, "is_provisional": True}
    assert passes_export_gate("ThreatActor", props, floor=0.3) is False


def test_below_floor_inferred_edge_excluded():
    props = {"confidence": 0.1}
    assert passes_export_gate("EDGE", props, floor=0.3) is False


def test_at_or_above_floor_passes():
    props = {"confidence": 0.3}
    assert passes_export_gate("EDGE", props, floor=0.3) is True


def test_pruned_object_excluded_regardless_of_confidence():
    props = {"confidence": 0.95, "prune_candidate": True}
    assert passes_export_gate("CVE", props, floor=0.3) is False


def test_object_refs_omits_gated_out_entities_not_dangling():
    candidates = ["vulnerability--a", "intrusion-set--b", "malware--c"]
    exported = {"vulnerability--a", "malware--c"}  # intrusion-set--b gated out
    result = filter_object_refs(candidates, exported)
    assert result == ["vulnerability--a", "malware--c"]
