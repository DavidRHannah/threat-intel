from src.scoring.formulas import relevance
from src.scoring.knobs import RelevanceKnobs

K = RelevanceKnobs(
    w_novelty=0.5, w_credibility=0.25, w_centrality=0.25,
    novelty_halflife_days=7.0, centrality_saturation_c=10.0,
)


def _rel(**kw):
    args = dict(age_days=0.0, credibility=0.0, assertion_degree=0, knobs=K)
    args.update(kw)
    return relevance(**args)


def test_novelty_is_a_true_halflife():
    """Spec C2: one half-life must halve the value, not decay it to 0.368."""
    assert _rel(age_days=7.0).novelty == 0.5
    assert _rel(age_days=14.0).novelty == 0.25


def test_brand_new_entity_scores_maximum_novelty():
    assert _rel(age_days=0.0).novelty == 1.0


def test_fr_es_06_centrality_reflects_assertion_degree_not_article_count():
    """FR-ES-06: an entity in 1000 articles but with few assertion edges has low
    centrality. Article count never reaches this function -- only assertion_degree does,
    which is the structural guarantee that press coverage cannot inflate centrality."""
    r = _rel(assertion_degree=1)
    assert r.centrality == 0.1


def test_centrality_saturates_at_c():
    assert _rel(assertion_degree=10).centrality == 1.0
    assert _rel(assertion_degree=999).centrality == 1.0


def test_weighted_combination():
    r = _rel(age_days=0.0, credibility=1.0, assertion_degree=10)
    assert r.score == 1.0
    assert r.novelty == 1.0 and r.credibility == 1.0 and r.centrality == 1.0


def test_credibility_passes_through_clamped():
    assert _rel(credibility=1.5).credibility == 1.0
    assert _rel(credibility=-0.5).credibility == 0.0


def test_negative_age_is_clamped_to_zero():
    """A published_at in the future (bad feed data) must not produce novelty > 1."""
    assert _rel(age_days=-30.0).novelty == 1.0
