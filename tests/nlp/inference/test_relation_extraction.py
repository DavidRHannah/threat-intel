from unittest.mock import MagicMock, patch

from src.nlp.inference.relation_extraction import (
    CandidateRelation,
    extract_relations,
    validate_and_map,
)
from src.nlp.messages import ResolvedEntity


def _mock_response(tool_input):
    resp = MagicMock()
    block = MagicMock(type="tool_use", input=tool_input)
    resp.content = [block]
    resp.stop_reason = "tool_use"
    return resp


@patch("src.nlp.inference.relation_extraction.anthropic.Anthropic")
def test_actor_and_cve_costory_asks_llm_which_entities_relate(mock_anthropic_cls):
    # FR-INF-01: a story co-mentioning an actor + CVE is sent to the LLM (entities +
    # representative text as user content, never folded into `system`) and the LLM's
    # judgment on relatedness/how/direction/strength is returned as candidates.
    mock_client = mock_anthropic_cls.return_value
    mock_client.messages.create.return_value = _mock_response(
        {
            "candidates": [
                {
                    "entity_a": "threat_actor:apt28",
                    "entity_b": "cve:cve-2026-1234",
                    "relationship": "exploits",
                    "direction": "b_to_a",
                    "assertion_strength": 0.9,
                    "polarity": "asserted",
                }
            ]
        }
    )
    entities = [
        ResolvedEntity(
            canonical_node_key="threat_actor:apt28",
            entity_type="threat_actor",
            resolution_status="resolved",
            node_confidence=0.9,
        ),
        ResolvedEntity(
            canonical_node_key="cve:cve-2026-1234",
            entity_type="cve",
            resolution_status="resolved",
            node_confidence=1.0,
        ),
    ]
    text = "APT28 was observed exploiting CVE-2026-1234 in the wild."

    candidates = extract_relations(text, entities, client=mock_client)

    assert len(candidates) == 1
    assert candidates[0].relationship == "exploits"
    assert candidates[0].polarity == "asserted"

    call_kwargs = mock_client.messages.create.call_args.kwargs
    system_arg = call_kwargs.get("system", "")
    user_content = call_kwargs["messages"][0]["content"]
    # article text + entities must be passed as user-content data, never in `system`
    assert text not in system_arg
    assert text in user_content
    assert "threat_actor:apt28" in user_content
    assert "cve:cve-2026-1234" in user_content


def test_ioc_to_ioc_candidate_has_no_catalog_edge_and_is_dropped():
    # FR-INF-02: schema validation drops candidates with no Layer 2 catalog edge for
    # the endpoint type pair (two IOCs is off-schema).
    candidate = CandidateRelation(
        entity_a={"canonical_node_key": "ioc:1.2.3.4", "entity_type": "ioc"},
        entity_b={"canonical_node_key": "ioc:evil.com", "entity_type": "ioc"},
        relationship="related",
        direction="a_to_b",
        assertion_strength=0.8,
        polarity="asserted",
    )

    assert validate_and_map(candidate) is None


def test_negated_relationship_produces_no_edge():
    # FR-INF-03: "X is not linked to Y" -> LLM reports polarity=negated -> no edge.
    candidate = CandidateRelation(
        entity_a={"canonical_node_key": "threat_actor:apt28", "entity_type": "threat_actor"},
        entity_b={"canonical_node_key": "cve:cve-2026-1234", "entity_type": "cve"},
        relationship="exploits",
        direction="b_to_a",
        assertion_strength=0.9,
        polarity="negated",
    )

    assert validate_and_map(candidate) is None


def test_hedged_relationship_discounts_assertion_strength():
    # FR-INF-03: "suspected to exploit" -> polarity=hedged -> edge written but discounted.
    candidate = CandidateRelation(
        entity_a={"canonical_node_key": "threat_actor:apt28", "entity_type": "threat_actor"},
        entity_b={"canonical_node_key": "cve:cve-2026-1234", "entity_type": "cve"},
        relationship="exploits",
        direction="b_to_a",
        assertion_strength=0.9,
        polarity="hedged",
    )

    mapped = validate_and_map(candidate)

    assert mapped is not None
    assert mapped.assertion_strength < 0.9


def test_asserted_cve_actor_maps_to_exploited_by_cve_rooted():
    # EXPLOITED_BY is CVE-rooted regardless of the order the LLM names the entities.
    candidate = CandidateRelation(
        entity_a={"canonical_node_key": "threat_actor:apt28", "entity_type": "threat_actor"},
        entity_b={"canonical_node_key": "cve:cve-2026-1234", "entity_type": "cve"},
        relationship="exploits",
        direction="a_to_b",
        assertion_strength=0.9,
        polarity="asserted",
    )

    mapped = validate_and_map(candidate)

    assert mapped is not None
    assert mapped.edge_type == "EXPLOITED_BY"
    assert mapped.start_key == "cve:cve-2026-1234"
    assert mapped.end_key == "threat_actor:apt28"
    assert mapped.assertion_strength == 0.9
    assert mapped.start_label == "CVE"
    assert mapped.end_label == "ThreatActor"


def test_uses_is_consumer_rooted():
    candidate = CandidateRelation(
        entity_a={"canonical_node_key": "ttp:t1566", "entity_type": "ttp"},
        entity_b={"canonical_node_key": "threat_actor:apt28", "entity_type": "threat_actor"},
        relationship="uses",
        direction="a_to_b",
        assertion_strength=0.7,
        polarity="asserted",
    )

    mapped = validate_and_map(candidate)

    assert mapped is not None
    assert mapped.edge_type == "USES"
    assert mapped.start_key == "threat_actor:apt28"
    assert mapped.end_key == "ttp:t1566"
    assert mapped.start_label == "ThreatActor"
    assert mapped.end_label == "TTP"


def test_malware_family_to_ioc_sample_keyword_maps_to_has_sample():
    # MalwareFamily->IOC is ambiguous between HAS_SAMPLE and COMMUNICATES_WITH;
    # disambiguated by the LLM's free-text relationship label.
    candidate = CandidateRelation(
        entity_a={"canonical_node_key": "malware_family:emotet", "entity_type": "malware_family"},
        entity_b={"canonical_node_key": "ioc:deadbeef", "entity_type": "ioc"},
        relationship="drops a malicious file with hash",
        direction="a_to_b",
        assertion_strength=0.8,
        polarity="asserted",
    )

    mapped = validate_and_map(candidate)

    assert mapped is not None
    assert mapped.edge_type == "HAS_SAMPLE"
    assert mapped.start_key == "malware_family:emotet"
    assert mapped.end_key == "ioc:deadbeef"
    assert mapped.start_label == "MalwareFamily"
    assert mapped.end_label == "IOC"


def test_malware_family_to_ioc_c2_keyword_maps_to_communicates_with():
    candidate = CandidateRelation(
        entity_a={"canonical_node_key": "malware_family:emotet", "entity_type": "malware_family"},
        entity_b={"canonical_node_key": "ioc:1.2.3.4", "entity_type": "ioc"},
        relationship="uses as a C2 callback server",
        direction="a_to_b",
        assertion_strength=0.8,
        polarity="asserted",
    )

    mapped = validate_and_map(candidate)

    assert mapped is not None
    assert mapped.edge_type == "COMMUNICATES_WITH"
    assert mapped.start_key == "malware_family:emotet"
    assert mapped.end_key == "ioc:1.2.3.4"
    assert mapped.start_label == "MalwareFamily"
    assert mapped.end_label == "IOC"


def test_malware_family_to_ioc_with_no_disambiguating_keyword_is_dropped():
    # Ambiguous type-pair (MalwareFamily->IOC) whose relationship label matches
    # neither HAS_SAMPLE nor COMMUNICATES_WITH keywords: drop rather than guess.
    candidate = CandidateRelation(
        entity_a={"canonical_node_key": "malware_family:emotet", "entity_type": "malware_family"},
        entity_b={"canonical_node_key": "ioc:1.2.3.4", "entity_type": "ioc"},
        relationship="is related to",
        direction="a_to_b",
        assertion_strength=0.8,
        polarity="asserted",
    )

    assert validate_and_map(candidate) is None


@patch("src.nlp.inference.relation_extraction.anthropic.Anthropic")
def test_llm_failure_propagates_uncaught(mock_anthropic_cls):
    mock_client = mock_anthropic_cls.return_value
    mock_client.messages.create.side_effect = TimeoutError("simulated timeout")
    import pytest

    entities = [
        ResolvedEntity(
            canonical_node_key="cve:cve-2026-1234",
            entity_type="cve",
            resolution_status="resolved",
            node_confidence=1.0,
        )
    ]
    with pytest.raises(TimeoutError):
        extract_relations("text", entities, client=mock_client)
