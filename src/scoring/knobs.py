"""Typed accessors over the scoring knobs (config/scoring.yaml -> env vars -> get_config).

Frozen dataclasses rather than bare get_config calls at each use site: the formulas in
formulas.py stay pure by taking a knob object as an argument, which is what lets every
FR-ES acceptance test run with no environment at all.
"""

from dataclasses import dataclass

from src.common.config import get_config

# No caching here on purpose: get_config is already lru_cached, so building a knob object
# is a handful of dict lookups. Caching the dataclass too would only add a cache_clear()
# dance to every test that overrides an env var.


def _f(name: str, default: str) -> float:
    return float(get_config(name, default=default))


def _check_weights(**weights: float) -> None:
    """Weights within a family must sum to 1.0, or clamp01 silently truncates every
    high score to 1.0 and the band thresholds stop meaning anything."""
    total = sum(weights.values())
    if abs(total - 1.0) > 1e-9:
        pairs = ", ".join(f"{k}={v}" for k, v in sorted(weights.items()))
        raise ValueError(f"scoring weights must sum to 1.0, got {total} ({pairs})")


@dataclass(frozen=True)
class SeverityKnobs:
    w_impact: float
    w_likelihood: float
    w_adoption: float
    adoption_saturation_k: float
    kev_floor: float
    band_critical: float
    band_high: float
    band_medium: float

    @classmethod
    def from_config(cls) -> "SeverityKnobs":
        k = cls(
            w_impact=_f("w_impact", "0.3"),
            w_likelihood=_f("w_likelihood", "0.5"),
            w_adoption=_f("w_adoption", "0.2"),
            adoption_saturation_k=_f("adoption_saturation_k", "5.0"),
            kev_floor=_f("kev_floor", "0.6"),
            band_critical=_f("band_critical", "0.8"),
            band_high=_f("band_high", "0.6"),
            band_medium=_f("band_medium", "0.4"),
        )
        _check_weights(
            w_impact=k.w_impact, w_likelihood=k.w_likelihood, w_adoption=k.w_adoption
        )
        return k


@dataclass(frozen=True)
class RelevanceKnobs:
    w_novelty: float
    w_credibility: float
    w_centrality: float
    novelty_halflife_days: float
    centrality_saturation_c: float

    @classmethod
    def from_config(cls) -> "RelevanceKnobs":
        k = cls(
            w_novelty=_f("w_novelty", "0.5"),
            w_credibility=_f("w_credibility", "0.25"),
            w_centrality=_f("w_centrality", "0.25"),
            novelty_halflife_days=_f("novelty_halflife_days", "7.0"),
            centrality_saturation_c=_f("centrality_saturation_c", "10.0"),
        )
        _check_weights(
            w_novelty=k.w_novelty,
            w_credibility=k.w_credibility,
            w_centrality=k.w_centrality,
        )
        return k


@dataclass(frozen=True)
class ConfidenceKnobs:
    decay_halflife_days: float
    prune_confidence_floor: float
    prune_stale_days: float
    edge_confidence_floor: float

    @classmethod
    def from_config(cls) -> "ConfidenceKnobs":
        # No _check_weights: these are independent thresholds, not a weighted blend.
        return cls(
            decay_halflife_days=_f("decay_halflife_days", "180.0"),
            prune_confidence_floor=_f("prune_confidence_floor", "0.2"),
            prune_stale_days=_f("prune_stale_days", "90.0"),
            edge_confidence_floor=_f("edge_confidence_floor", "0.1"),
        )
