from src.assets.matching import version_satisfies


def _match(**overrides):
    base = {
        "vendor": "acme", "product": "x", "version": None,
        "version_start_including": None, "version_start_excluding": None,
        "version_end_including": None, "version_end_excluding": None,
        "vulnerable": True,
    }
    base.update(overrides)
    return base


def test_exact_pin_matches_equal_version():
    assert version_satisfies("1.2.0", _match(version="1.2.0")) is True


def test_exact_pin_rejects_different_version():
    assert version_satisfies("1.2.1", _match(version="1.2.0")) is False


def test_range_including_boundaries():
    m = _match(version_start_including="17.3.0", version_end_excluding="17.3.5")
    assert version_satisfies("17.3.0", m) is True   # start inclusive
    assert version_satisfies("17.3.4", m) is True
    assert version_satisfies("17.3.5", m) is False  # end exclusive
    assert version_satisfies("17.2.9", m) is False  # below start


def test_range_excluding_start_boundary():
    m = _match(version_start_excluding="1.0.0", version_end_including="2.0.0")
    assert version_satisfies("1.0.0", m) is False
    assert version_satisfies("1.0.1", m) is True
    assert version_satisfies("2.0.0", m) is True


def test_vulnerable_false_never_matches():
    m = _match(version="1.2.0", vulnerable=False)
    assert version_satisfies("1.2.0", m) is False


def test_no_constraint_at_all_matches_any_version():
    assert version_satisfies("99.99.99", _match()) is True


def test_mixed_length_components_compares_correctly():
    m = _match(version_start_including="17.3", version_end_excluding="17.3.5")
    assert version_satisfies("17.3.0", m) is True
    assert version_satisfies("17.3", m) is True
    assert version_satisfies("17.4", m) is False


def test_non_numeric_component_falls_back_to_string_compare():
    # Real-world messy version strings must not raise.
    m = _match(version_start_including="17.3.1a", version_end_excluding="17.3.2")
    assert version_satisfies("17.3.1a", m) is True
    assert version_satisfies("17.3.1b", m) is True  # "1a" < "1b" lexically, both < "3.2"... see step 3 note
