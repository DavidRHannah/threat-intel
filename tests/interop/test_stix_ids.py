import uuid

from src.interop.stix_ids import STIX_TYPE_BY_LABEL, stix_id


def test_same_natural_key_yields_same_id():
    ns = "5a2c1f2e-6b8a-4b0a-9c3e-2f6a7d8e9b10"
    first = stix_id("CVE", "CVE-2026-1234", namespace=ns)
    second = stix_id("CVE", "CVE-2026-1234", namespace=ns)
    assert first == second


def test_id_shape_matches_stix_type():
    ns = "5a2c1f2e-6b8a-4b0a-9c3e-2f6a7d8e9b10"
    result = stix_id("ThreatActor", "lazarus", namespace=ns)
    assert result.startswith("intrusion-set--")
    uuid.UUID(result.split("--", 1)[1])  # raises if not a valid UUID


def test_different_labels_same_value_yield_different_ids():
    """A ThreatActor 'lazarus' and a MalwareFamily 'lazarus' must not collide -- merge_key
    is shared across labels (technical-specification.md sec 3.1)."""
    ns = "5a2c1f2e-6b8a-4b0a-9c3e-2f6a7d8e9b10"
    actor_id = stix_id("ThreatActor", "lazarus", namespace=ns)
    malware_id = stix_id("MalwareFamily", "lazarus", namespace=ns)
    assert actor_id != malware_id


def test_every_scored_and_exportable_label_covered():
    for label in (
        "CVE", "TTP", "IOC", "ThreatActor", "MalwareFamily", "Campaign", "Article", "Source",
    ):
        assert label in STIX_TYPE_BY_LABEL
