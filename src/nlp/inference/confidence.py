"""Per-story confidence contribution bounds checking (FR-INF-04, FR-INF-05, FR-INF-06).

The `compute_contribution` function clamps assertion_strength (already polarity-discounted
by inference Stage 4.1 for hedged relationships) to [0.0, 1.0], providing a defensive guard
against malformed LLM responses. The result is passed to L3's `upsert_inferred_assertion`,
which handles the noisy-OR combination and idempotency check.
"""

from src.nlp.inference.relation_extraction import CandidateRelation


def compute_contribution(candidate: CandidateRelation) -> float:
    """Clamp assertion_strength to [0.0, 1.0].

    Args:
        candidate: A CandidateRelation with assertion_strength (already polarity-discounted
                   by Step 4.1 for hedged relationships).

    Returns:
        The assertion_strength clamped to [0.0, 1.0].
    """
    return max(0.0, min(1.0, candidate.assertion_strength))
