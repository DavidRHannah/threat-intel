"""Pure scoring maths. NO I/O -- this module must never import neo4j or boto3.

That purity is the point: every FR-ES acceptance criterion becomes a unit test that runs
without Docker, and the event path and the sweep path provably share one implementation.

The knob types are imported under TYPE_CHECKING, never at runtime. They are used ONLY in
annotations, and a runtime import would reach src.scoring.knobs -> src.common.config ->
boto3, making this module transitively I/O-bound and failing FR-ES-01's import guard.
Deferring boto3 inside get_config would also silence the guard, but it makes this
module's purity depend on how a shared module happens to write its imports -- one
top-level `import boto3` added to config.py later and the guarantee is silently gone.
TYPE_CHECKING makes the purity structural instead.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.scoring.knobs import RelevanceKnobs, SeverityKnobs


def clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


@dataclass(frozen=True)
class SeverityResult:
    score: float | None
    band: str
    impact: float | None
    likelihood: float | None
    adoption: float
    is_provisional: bool


def _band(score: float, knobs: SeverityKnobs) -> str:
    if score >= knobs.band_critical:
        return "critical"
    if score >= knobs.band_high:
        return "high"
    if score >= knobs.band_medium:
        return "medium"
    return "low"


def severity(
    *,
    cvss_score: float | None,
    epss_score: float | None,
    exploited_in_wild: bool,
    exploiter_count: int,
    knobs: SeverityKnobs,
) -> SeverityResult:
    """FR-ES-04 / FR-ES-05. Null handling follows spec §5.1's precedence table.

    A missing input is NEVER treated as a real 0 without `is_provisional` marking it.
    """
    adoption = clamp01(exploiter_count / knobs.adoption_saturation_k)

    if cvss_score is None:
        if not exploited_in_wild:
            # Nothing to compute from. Left unset until L1 enrichment lands, at which
            # point the node_write event triggers the first real computation.
            return SeverityResult(None, "unknown", None, None, adoption, False)
        # KEV without CVSS: honour FR-ES-04's floor rather than inventing a fake impact.
        return SeverityResult(
            knobs.kev_floor, _band(knobs.kev_floor, knobs), None, 1.0, adoption, True
        )

    impact = clamp01(cvss_score / 10.0)
    provisional = epss_score is None
    likelihood = 1.0 if exploited_in_wild else (0.0 if provisional else epss_score)

    score = clamp01(
        knobs.w_impact * impact
        + knobs.w_likelihood * likelihood
        + knobs.w_adoption * adoption
    )
    if exploited_in_wild:
        score = max(score, knobs.kev_floor)

    return SeverityResult(score, _band(score, knobs), impact, likelihood, adoption, provisional)


@dataclass(frozen=True)
class RelevanceResult:
    score: float
    novelty: float
    credibility: float
    centrality: float


def relevance(
    *,
    age_days: float,
    credibility: float,
    assertion_degree: int,
    knobs: RelevanceKnobs,
) -> RelevanceResult:
    """FR-ES-06. `age_days` is measured from the entity's most recent SIGNIFICANT event
    (`last_significant_event`, falling back to `first_seen`) -- not from `last_updated`,
    which routine re-enrichment would keep pinned at ~now forever.

    `assertion_degree` counts ONLY the seven assertion edge types
    (src/common/graph/edge_types.py). Evidence edges (MENTIONS/PUBLISHED_BY) and
    structural edges (CATEGORIZED_AS) are excluded by the caller's query: counting them
    would make centrality a proxy for press coverage, double-counting novelty and
    credibility, which already derive from mentions.
    """
    novelty = 0.5 ** (max(age_days, 0.0) / knobs.novelty_halflife_days)
    cred = clamp01(credibility)
    centrality = clamp01(assertion_degree / knobs.centrality_saturation_c)

    score = clamp01(
        knobs.w_novelty * novelty
        + knobs.w_credibility * cred
        + knobs.w_centrality * centrality
    )
    return RelevanceResult(score, novelty, cred, centrality)


def noisy_or(contributions: Iterable[float]) -> float:
    """FR-ES-08: confidence = 1 - product(1 - s_j) over distinct corroborating stories.

    Monotonic and order-independent: the result depends only on WHICH contributions are
    in the set, never on the order they arrived in. That is the property the caller
    relies on -- `confidence.refine_provisional_confidence` deliberately recomputes from
    the full stored per-cluster set on every event rather than folding each new story
    into the previous value, because §5.3 defines `s_j` as the MAX over a cluster's
    mentioning articles and an incremental fold cannot raise a cluster it has already
    counted.

    Bounded below 1 in exact arithmetic, but NOT in float: with s_j = 0.5 the product
    underflows the double's precision and this returns exactly 1.0 from 54 contributions
    on. Nothing depends on the strict bound -- a node's provisional-ness is the
    `:Provisional` LABEL, not a confidence below some threshold -- but do not write a
    guard or a test that assumes `< 1.0` for large N.
    """
    complement = 1.0
    for s in contributions:
        complement *= 1.0 - clamp01(s)
    return clamp01(1.0 - complement)


def decay(
    *,
    inferred_confidence: float,
    days_since_last_confirmed: float | None,
    halflife_days: float,
) -> float:
    """FR-ES-09. Computed, NEVER accumulated.

    The naive alternative -- multiplying the stored value by a decay factor each sweep --
    is not idempotent: a retry, an SQS redelivery, or two sweeps in one day compound it.
    Here the input is the immutable base that Inference owns, so any number of runs on
    the same day yields the same answer.

    `days_since_last_confirmed=None` (edge never confirmed) means no elapsed time to
    decay over, so the base passes through undecayed rather than raising.
    """
    if days_since_last_confirmed is None:
        return clamp01(inferred_confidence)
    elapsed = max(days_since_last_confirmed, 0.0)
    return clamp01(inferred_confidence * 0.5 ** (elapsed / halflife_days))


def effective_confidence(
    *,
    authoritative_confidence: float,
    inferred_confidence: float,
    days_since_last_confirmed: float | None,
    halflife_days: float,
) -> float:
    """The L2/L3 max rule, re-applied after decay (technical-specification.md §3.2).

    An edge also backed by a feed stays pinned at that feed's credibility regardless of
    how long ago the inferred contribution was last corroborated.
    """
    decayed = decay(
        inferred_confidence=inferred_confidence,
        days_since_last_confirmed=days_since_last_confirmed,
        halflife_days=halflife_days,
    )
    return max(clamp01(authoritative_confidence), decayed)
