"""Tests for per-story confidence contribution bounds checking (FR-INF-04, FR-INF-05, FR-INF-06)."""

from src.nlp.inference.confidence import compute_contribution
from src.nlp.inference.relation_extraction import CandidateRelation


def test_in_range_assertion_strength_passes_through():
    """An assertion_strength in [0.0, 1.0] passes through unchanged."""
    candidate = CandidateRelation(
        entity_a={"canonical_node_key": "a", "entity_type": "threat_actor"},
        entity_b={"canonical_node_key": "b", "entity_type": "malware_family"},
        relationship="develops",
        direction="a_to_b",
        assertion_strength=0.75,
        polarity="asserted",
    )
    assert compute_contribution(candidate) == 0.75


def test_out_of_range_assertion_strength_is_clamped():
    """An assertion_strength outside [0.0, 1.0] is clamped, not raised."""
    candidate_high = CandidateRelation(
        entity_a={"canonical_node_key": "a", "entity_type": "threat_actor"},
        entity_b={"canonical_node_key": "b", "entity_type": "malware_family"},
        relationship="develops",
        direction="a_to_b",
        assertion_strength=1.5,
        polarity="asserted",
    )
    assert compute_contribution(candidate_high) == 1.0

    candidate_low = CandidateRelation(
        entity_a={"canonical_node_key": "a", "entity_type": "threat_actor"},
        entity_b={"canonical_node_key": "b", "entity_type": "malware_family"},
        relationship="develops",
        direction="a_to_b",
        assertion_strength=-0.2,
        polarity="asserted",
    )
    assert compute_contribution(candidate_low) == 0.0
