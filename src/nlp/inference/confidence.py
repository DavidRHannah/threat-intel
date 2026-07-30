"""Per-story confidence contribution bounds checking (FR-INF-04, FR-INF-05, FR-INF-06).

The `compute_contribution` function clamps a `MappedEdge.assertion_strength` --
the *post*-`validate_and_map` value, already polarity-discounted by
`validate_and_map` for `hedged` relationships (`relation_extraction.py`'s
`_HEDGE_DISCOUNT`) -- to [0.0, 1.0], providing a defensive guard against a
malformed LLM response or mapping bug. The result is passed to L3's
`upsert_inferred_assertion`, which handles the noisy-OR combination and
idempotency check.

Takes a `MappedEdge`, not the raw `CandidateRelation`, on purpose:
`CandidateRelation.assertion_strength` is the LLM's raw, un-discounted value --
`validate_and_map` applies the hedge discount to a local variable and stores
the result only on the `MappedEdge` it returns, never mutating the
`CandidateRelation` it was given. Clamping `candidate.assertion_strength`
instead would silently write every hedged relation's edge at full strength
(fixed 2026-07-30, review round 1 -- see `.superpowers/sdd/task-4.4-report.md`).
"""

from src.nlp.inference.relation_extraction import MappedEdge


def compute_contribution(mapped: MappedEdge) -> float:
    """Clamp `mapped.assertion_strength` to [0.0, 1.0].

    Args:
        mapped: A MappedEdge (validate_and_map's output) whose assertion_strength
                is already polarity-discounted for hedged relationships.

    Returns:
        assertion_strength clamped to [0.0, 1.0].
    """
    return max(0.0, min(1.0, mapped.assertion_strength))
