from src.nlp.extraction.deterministic import extract_deterministic


def test_cve_extraction_near_full_confidence():
    mentions = extract_deterministic("Attackers exploited CVE-2026-1234 in the wild.")
    cve_mentions = [m for m in mentions if m.entity_type == "cve"]
    assert len(cve_mentions) == 1
    assert cve_mentions[0].surface_text == "CVE-2026-1234"
    assert cve_mentions[0].extraction_confidence >= 0.95


def test_ttp_subtechnique_distinct_from_parent():
    mentions = extract_deterministic("The actor used T1566.001 as well as T1566 generally.")
    ttp_values = sorted(m.surface_text for m in mentions if m.entity_type == "ttp")
    assert ttp_values == ["T1566", "T1566.001"]


def test_defanged_ipv4_is_refanged_and_classified():
    mentions = extract_deterministic("Traffic was seen to 1.2.3[.]4 during the campaign.")
    ioc_mentions = [m for m in mentions if m.entity_type == "ioc"]
    assert len(ioc_mentions) == 1
    assert ioc_mentions[0].surface_text == "1.2.3.4"
    assert ioc_mentions[0].context_snippet


def test_rfc1918_ip_is_dropped():
    mentions = extract_deterministic("Internal host 192.168.1.1 talked to the C2.")
    ioc_values = [m.surface_text for m in mentions if m.entity_type == "ioc"]
    assert "192.168.1.1" not in ioc_values


def test_benign_allowlisted_domain_is_dropped():
    mentions = extract_deterministic("The malware fetched an update from github.com.")
    ioc_values = [m.surface_text for m in mentions if m.entity_type == "ioc"]
    assert "github.com" not in ioc_values


def test_defanged_domain_scores_higher_confidence_than_bare_domain():
    defanged = extract_deterministic("The domain evil[.]com hosted the payload.")
    bare = extract_deterministic("The domain example.com hosted the payload.")
    defanged_ioc = next(m for m in defanged if m.entity_type == "ioc")
    bare_ioc = next(m for m in bare if m.entity_type == "ioc")
    assert defanged_ioc.extraction_confidence > bare_ioc.extraction_confidence


def test_cve_mentioned_five_times_yields_one_mention():
    text = " ".join(["CVE-2026-9999 was patched."] * 5)
    mentions = extract_deterministic(text)
    cve_mentions = [m for m in mentions if m.entity_type == "cve"]
    assert len(cve_mentions) == 1
