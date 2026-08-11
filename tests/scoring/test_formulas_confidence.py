import pytest

from src.scoring.formulas import decay, effective_confidence, noisy_or


def test_noisy_or_of_nothing_is_zero():
    assert noisy_or([]) == 0.0


def test_noisy_or_rises_toward_one_with_corroboration():
    """FR-ES-08: a provisional entity named across three credible distinct stories
    rises toward 1."""
    one = noisy_or([0.8])
    three = noisy_or([0.8, 0.8, 0.8])
    assert one == pytest.approx(0.8)
    assert three > 0.99
    assert three < 1.0          # holds at this N; see the saturation test below


def test_noisy_or_saturates_at_exactly_one_in_float():
    """The bound below 1 is exact-arithmetic only. Pinned so nobody re-derives the old
    "bounded strictly below 1" claim and writes a guard on it: at s=0.5 the complement
    underflows the double's precision and this returns exactly 1.0 from 54 on."""
    assert noisy_or([0.5] * 53) < 1.0
    assert noisy_or([0.5] * 54) == 1.0


def test_noisy_or_is_monotonic_and_order_independent():
    assert noisy_or([0.3, 0.7]) == noisy_or([0.7, 0.3])
    assert noisy_or([0.3, 0.7]) > noisy_or([0.3])


def test_noisy_or_of_a_single_low_credibility_mention_stays_low():
    assert noisy_or([0.1]) == pytest.approx(0.1)


def test_decay_is_a_true_halflife():
    assert decay(inferred_confidence=0.8, days_since_last_confirmed=180.0,
                 halflife_days=180.0) == 0.4


def test_fr_es_09_decay_is_idempotent_because_it_reads_an_immutable_base():
    """FR-ES-09: Given the decay sweep runs twice in one day, Then the edge's effective
    confidence is identical. Provable as a PURE test precisely because decay never reads
    its own previous output -- only the immutable base and a timestamp."""
    args = dict(inferred_confidence=0.8, days_since_last_confirmed=90.0,
                halflife_days=180.0)
    assert decay(**args) == decay(**args) == decay(**args)


def test_fr_es_09_authoritative_edges_do_not_decay():
    """A feed-backed edge is unchanged: MITRE saying an actor uses a technique does not
    get less true with age."""
    assert effective_confidence(
        authoritative_confidence=1.0, inferred_confidence=0.8,
        days_since_last_confirmed=10_000.0, halflife_days=180.0,
    ) == 1.0


def test_effective_confidence_takes_the_max_of_both_components():
    assert effective_confidence(
        authoritative_confidence=0.0, inferred_confidence=0.8,
        days_since_last_confirmed=0.0, halflife_days=180.0,
    ) == 0.8


def test_never_confirmed_edge_does_not_crash():
    """last_confirmed can be absent on a hand-written or legacy edge."""
    assert decay(inferred_confidence=0.8, days_since_last_confirmed=None,
                 halflife_days=180.0) == 0.8


def test_decay_clamps_negative_elapsed_time_to_zero():
    """The symmetric case of `test_negative_age_is_clamped_to_zero` in relevance():
    out-of-order delivery or clock skew can hand `decay` a `last_confirmed` in the
    future, which must not be treated as a NEGATIVE elapsed time -- that would make
    confidence rise with age instead of falling toward it."""
    assert decay(inferred_confidence=0.8, days_since_last_confirmed=-30.0,
                 halflife_days=180.0) == 0.8
