from src.scoring.formulas import severity
from src.scoring.knobs import SeverityKnobs

K = SeverityKnobs(
    w_impact=0.3, w_likelihood=0.5, w_adoption=0.2, adoption_saturation_k=5.0,
    kev_floor=0.6, band_critical=0.8, band_high=0.6, band_medium=0.4,
)


def _sev(**kw):
    args = dict(cvss_score=None, epss_score=None, exploited_in_wild=False,
                exploiter_count=0, knobs=K)
    args.update(kw)
    return severity(**args)


def test_fr_es_04_kev_listed_cve_always_scores_at_least_the_floor():
    """FR-ES-04: Given a KEV-listed CVE, When scored, Then severity_score >= 0.6."""
    r = _sev(cvss_score=1.0, epss_score=0.0, exploited_in_wild=True)
    assert r.score >= 0.6
    assert r.band == "high"


def test_fr_es_04_kev_plus_high_impact_reaches_critical_without_a_special_case():
    r = _sev(cvss_score=9.8, epss_score=0.91, exploited_in_wild=True, exploiter_count=5)
    assert r.score >= 0.8
    assert r.band == "critical"


def test_fr_es_05_bare_stub_is_unknown_not_low():
    """FR-ES-05: Given a lazy-created CVE stub, Then its band is `unknown`, not `low`."""
    r = _sev()
    assert r.band == "unknown"
    assert r.score is None


def test_kev_without_cvss_still_honours_the_floor():
    """Spec §5.1 row 1: reconciles FR-ES-05 with FR-ES-04's own acceptance."""
    r = _sev(exploited_in_wild=True)
    assert r.score == 0.6
    assert r.band == "high"
    assert r.is_provisional is True
    assert r.impact is None


def test_cvss_present_epss_missing_computes_and_flags_provisional():
    r = _sev(cvss_score=8.0)
    assert r.is_provisional is True
    assert r.likelihood == 0.0        # never treated as a real 0 without the flag
    assert r.score == 0.3 * 0.8


def test_adoption_saturates_at_k():
    a = _sev(cvss_score=5.0, epss_score=0.1, exploiter_count=5).adoption
    b = _sev(cvss_score=5.0, epss_score=0.1, exploiter_count=500).adoption
    assert a == b == 1.0


def test_bands_partition_the_range():
    assert _sev(cvss_score=0.0, epss_score=0.0).band == "low"
    assert _sev(cvss_score=10.0, epss_score=0.2).band == "medium"
    assert _sev(cvss_score=10.0, epss_score=1.0).band == "critical"


def test_is_a_pure_function():
    """FR-ES-04 idempotency: same inputs, same output, no hidden state."""
    kw = dict(cvss_score=7.5, epss_score=0.4, exploited_in_wild=False, exploiter_count=2)
    assert _sev(**kw) == _sev(**kw)


def test_fr_es_01_formulas_never_import_an_http_client():
    """FR-ES-01: the scoring layer computes from the graph and makes NO external API
    calls. Enforced mechanically rather than by review, so a future edit that reaches
    for a feed client fails here instead of shipping.

    Subprocess, not sys.modules: this process has already imported half the codebase, so
    an in-process check would pass no matter what formulas.py pulls in. Mirrors
    tests/nlp/extraction/test_handler.py::test_handler_module_never_imports_neo4j.
    """
    import subprocess
    import sys

    probe = (
        "import sys; import src.scoring.formulas; "
        "banned = {'httpx', 'requests', 'urllib3', 'boto3', 'neo4j', 'feedparser'}; "
        "hit = banned & set(sys.modules); "
        "print(','.join(sorted(hit)))"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "", f"formulas.py imported: {out.stdout.strip()}"
