import pytest

from src.common.config import get_config
from src.scoring.knobs import ConfidenceKnobs, RelevanceKnobs, SeverityKnobs


def test_severity_knobs_defaults(monkeypatch):
    monkeypatch.delenv("CROSSROADS_W_IMPACT", raising=False)
    k = SeverityKnobs.from_config()
    assert (k.w_impact, k.w_likelihood, k.w_adoption) == (0.3, 0.5, 0.2)
    assert k.kev_floor == 0.6
    assert (k.band_critical, k.band_high, k.band_medium) == (0.8, 0.6, 0.4)


def test_relevance_knobs_defaults():
    k = RelevanceKnobs.from_config()
    assert (k.w_novelty, k.w_credibility, k.w_centrality) == (0.5, 0.25, 0.25)


def test_confidence_knobs_defaults():
    k = ConfidenceKnobs.from_config()
    assert k.decay_halflife_days == 180.0


def test_env_var_overrides_default(monkeypatch):
    monkeypatch.setenv("CROSSROADS_KEV_FLOOR", "0.75")
    get_config.cache_clear()
    assert SeverityKnobs.from_config().kev_floor == 0.75


def test_weights_not_summing_to_one_is_rejected(monkeypatch):
    """A bad YAML edit must fail loudly at load, not silently emit out-of-range scores."""
    monkeypatch.setenv("CROSSROADS_W_IMPACT", "0.9")
    get_config.cache_clear()
    with pytest.raises(ValueError, match="must sum to 1.0"):
        SeverityKnobs.from_config()
