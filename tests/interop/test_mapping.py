# tests/interop/test_mapping.py
from datetime import datetime, timezone

from src.interop.mapping import edge_to_stix, node_to_stix

_NS = "5a2c1f2e-6b8a-4b0a-9c3e-2f6a7d8e9b10"


def test_cve_maps_to_vulnerability_with_stix_confidence_scaled():
    props = {
        "cve_id": "CVE-2026-1234",
        "description": "A vulnerability",
        "confidence": 1.0,
        "last_updated": datetime(2026, 8, 1, tzinfo=timezone.utc),
        "first_seen": datetime(2026, 7, 1, tzinfo=timezone.utc),
    }
    obj = node_to_stix("CVE", props, namespace=_NS)
    assert obj.type == "vulnerability"
    assert obj.confidence == 100
    assert obj.name == "CVE-2026-1234"
    assert obj.id.startswith("vulnerability--")
    from src.interop.tlp import TLP_CLEAR

    assert TLP_CLEAR.id in obj.object_marking_refs


def test_ioc_maps_to_indicator_with_stix_pattern():
    props = {
        "value": "1.2.3.4",
        "ioc_type": "ip",
        "value_type_key": "1.2.3.4::ip",
        "confidence": 0.8,
        "last_updated": datetime(2026, 8, 1, tzinfo=timezone.utc),
        "first_seen": datetime(2026, 7, 1, tzinfo=timezone.utc),
    }
    obj = node_to_stix("IOC", props, namespace=_NS)
    assert obj.type == "indicator"
    assert obj.pattern == "[ipv4-addr:value = '1.2.3.4']"
    assert obj.pattern_type == "stix"
    assert obj.confidence == 80


def test_ioc_hash_pattern():
    props = {
        "value": "deadbeef" * 8,
        "ioc_type": "sha256_hash",
        "value_type_key": "x::sha256_hash",
        "confidence": 0.5,
        "last_updated": datetime(2026, 8, 1, tzinfo=timezone.utc),
        "first_seen": datetime(2026, 7, 1, tzinfo=timezone.utc),
    }
    obj = node_to_stix("IOC", props, namespace=_NS)
    assert obj.pattern == f"[file:hashes.'SHA-256' = '{'deadbeef' * 8}']"


def test_ioc_sha1_pattern():
    props = {
        "value": "a" * 40,
        "ioc_type": "sha1_hash",
        "value_type_key": "x::sha1_hash",
        "confidence": 0.5,
        "last_updated": datetime(2026, 8, 1, tzinfo=timezone.utc),
        "first_seen": datetime(2026, 7, 1, tzinfo=timezone.utc),
    }
    obj = node_to_stix("IOC", props, namespace=_NS)
    assert obj.pattern == f"[file:hashes.'SHA-1' = '{'a' * 40}']"


def test_ioc_ip_port_pattern_drops_port():
    props = {
        "value": "1.2.3.4:8080",
        "ioc_type": "ip:port",
        "value_type_key": "1.2.3.4:8080::ip:port",
        "confidence": 0.5,
        "last_updated": datetime(2026, 8, 1, tzinfo=timezone.utc),
        "first_seen": datetime(2026, 7, 1, tzinfo=timezone.utc),
    }
    obj = node_to_stix("IOC", props, namespace=_NS)
    assert obj.pattern == "[ipv4-addr:value = '1.2.3.4']"


def test_assertion_edge_maps_to_relationship_with_correct_type():
    start = {"merge_key": "lazarus"}
    end = {"cve_id": "CVE-2026-1234"}
    edge_props = {
        "confidence": 0.6,
        "last_updated": datetime(2026, 8, 1, tzinfo=timezone.utc),
        "first_observed": datetime(2026, 7, 1, tzinfo=timezone.utc),
    }
    rel = edge_to_stix(
        "EXPLOITED_BY", "CVE", end, "ThreatActor", start, edge_props, namespace=_NS,
    )
    # STIX convention flips direction: exploiter -> vulnerability (design.md Part 3).
    assert rel.relationship_type == "exploits"
    assert rel.source_ref.startswith("intrusion-set--")
    assert rel.target_ref.startswith("vulnerability--")
