"""Tests for per-story confidence contribution bounds checking (FR-INF-04, FR-INF-05, FR-INF-06).

compute_contribution takes a MappedEdge (validate_and_map's output), not the raw
CandidateRelation -- the hedge discount (FR-INF-03) is applied by validate_and_map onto the
MappedEdge it returns, never onto the CandidateRelation it was given.
"""

from src.nlp.inference.confidence import compute_contribution
from src.nlp.inference.relation_extraction import MappedEdge


def _mapped_edge(assertion_strength: float) -> MappedEdge:
    return MappedEdge(
        edge_type="USES",
        start_key="a",
        end_key="b",
        assertion_strength=assertion_strength,
        start_label="ThreatActor",
        end_label="MalwareFamily",
    )


def test_in_range_assertion_strength_passes_through():
    """An assertion_strength in [0.0, 1.0] passes through unchanged."""
    assert compute_contribution(_mapped_edge(0.75)) == 0.75


def test_out_of_range_assertion_strength_is_clamped():
    """An assertion_strength outside [0.0, 1.0] is clamped, not raised."""
    assert compute_contribution(_mapped_edge(1.5)) == 1.0
    assert compute_contribution(_mapped_edge(-0.2)) == 0.0


def test_hedge_discounted_strength_is_what_gets_clamped():
    """FR-INF-03: the hedge discount is applied by validate_and_map onto the MappedEdge
    it returns -- compute_contribution clamps that already-discounted value, not the raw
    CandidateRelation.assertion_strength the LLM reported."""
    # 0.9 raw * 0.5 hedge discount (relation_extraction._HEDGE_DISCOUNT) = 0.45
    assert compute_contribution(_mapped_edge(0.45)) == 0.45
