"""Tests for src.nlp.inference.handler (Inference Lambda handler, Phase 4
Step 4.4 of `plans/02-nlp.md`, FR-INF-06, FR-INF-07, FR-INF-08).

Integration tests against real Neo4j (Docker Compose) plus a moto DynamoDB
RE-cache table, mirroring `tests/nlp/resolution/test_handler.py` (real
Neo4j) and `tests/nlp/inference/test_re_cache.py` (moto fixture pattern).

`extract_relations` (the LLM boundary, already covered by
`tests/nlp/inference/test_relation_extraction.py`) is mocked here so these
tests exercise this handler's own responsibility: correctly invoking
`validate_and_map` and `upsert_inferred_assertion` (inside
`session.execute_write`) with the right start/end/rel_type, not L3's
noisy-OR/idempotency math (already proven in `plans/03-graph.md`'s suite).
"""

from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

from src.common.neo4j_driver import close_driver, get_driver
from src.nlp.inference.handler import _process_story_cluster
from src.nlp.inference.relation_extraction import CandidateRelation
from src.nlp.messages import ResolvedEntity, StoryCluster

_TEST_PREFIX = "inference-handler-test"


@pytest.fixture
def driver():
    d = get_driver()
    d.verify_connectivity()
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


@pytest.fixture
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")


@pytest.fixture
def re_cache_table(aws_credentials):
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="RECache",
            KeySchema=[{"AttributeName": "re_target_content_hash", "KeyType": "HASH"}],
            AttributeDefinitions=[
                {"AttributeName": "re_target_content_hash", "AttributeType": "S"}
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table


def _no_llm_needed():
    raise AssertionError("LLM client should not have been requested on a RE-cache hit")


def _unused_llm_client():
    """extract_relations is patched in these tests, so the real LLM client is never
    used -- but _process_story_cluster still calls get_llm_client() to produce the
    (unused) argument, so this stub must not raise."""
    return None


def _seed_article(driver, article_id, story_cluster_id, cleaned_text, content_hash):
    with driver.session() as s:
        s.run(
            "MERGE (a:Article {source_guid_key: $id}) "
            "SET a.test_fixture = true, a.story_cluster_id = $cluster_id, "
            "a.is_cluster_representative = true, a.cleaned_text = $text, "
            "a.content_hash = $hash",
            id=article_id,
            cluster_id=story_cluster_id,
            text=cleaned_text,
            hash=content_hash,
        ).consume()


def _seed_node(driver, label, key_prop, key_value):
    with driver.session() as s:
        s.run(
            f"MERGE (n:{label} {{{key_prop}: $value}}) SET n.test_fixture = true",
            value=key_value,
        ).consume()


def _edge_exists(driver, start_label, start_prop, start_value, rel_type, end_label, end_prop, end_value):
    with driver.session() as s:
        record = s.run(
            f"MATCH (a:{start_label} {{{start_prop}: $sv}})-[r:{rel_type}]->"
            f"(b:{end_label} {{{end_prop}: $ev}}) RETURN r",
            sv=start_value,
            ev=end_value,
        ).single()
    return record is not None


@patch("src.nlp.inference.handler.publish_graph_write")
def test_actor_and_cve_costory_creates_exploited_by_edge_with_inferred_origin(
    mock_publish, driver, re_cache_table
):
    # FR-INF-06: this handler correctly invokes upsert_inferred_assertion with the
    # right start/end/rel_type -- not re-testing L3's own noisy-OR/idempotency math.
    cve_id = "CVE-2099-40004"
    actor_key = "apt-handler-test"
    _seed_node(driver, "CVE", "cve_id", cve_id)
    _seed_node(driver, "ThreatActor", "merge_key", actor_key)

    article_id = f"{_TEST_PREFIX}::article-1"
    cluster_id = f"{_TEST_PREFIX}::cluster-1"
    _seed_article(driver, article_id, cluster_id, "APT was seen exploiting the CVE.", "hash-1")

    entities = [
        ResolvedEntity(cve_id, "cve", "resolved", 1.0),
        ResolvedEntity(actor_key, "threat_actor", "resolved", 0.9),
    ]
    story_cluster = StoryCluster(
        story_cluster_id=cluster_id, article_ids=[article_id], union_resolved_entities=entities
    )

    candidate = CandidateRelation(
        entity_a={"canonical_node_key": actor_key, "entity_type": "threat_actor"},
        entity_b={"canonical_node_key": cve_id, "entity_type": "cve"},
        relationship="exploits",
        direction="b_to_a",
        assertion_strength=0.9,
        polarity="asserted",
    )

    with patch(
        "src.nlp.inference.handler.extract_relations", return_value=[candidate]
    ) as mock_extract:
        _process_story_cluster(
            story_cluster.to_dict(), driver, re_cache_table, _unused_llm_client
        )
        mock_extract.assert_called_once()

    assert _edge_exists(
        driver, "CVE", "cve_id", cve_id, "EXPLOITED_BY", "ThreatActor", "merge_key", actor_key
    )
    with driver.session() as s:
        record = s.run(
            "MATCH (:CVE {cve_id: $cve_id})-[r:EXPLOITED_BY]->(:ThreatActor {merge_key: $actor_key}) "
            "RETURN r.origin AS origin",
            cve_id=cve_id,
            actor_key=actor_key,
        ).single()
    assert "inferred" in record["origin"]
    assert mock_publish.called


@patch("src.nlp.inference.handler.publish_graph_write")
def test_re_cache_hit_skips_extract_relations(mock_publish, driver, re_cache_table):
    # FR-INF-07: unchanged RE-target text (same content_hash) -> cache hit -> no LLM call.
    cve_id = "CVE-2099-50005"
    actor_key = "apt-handler-cache-test"
    _seed_node(driver, "CVE", "cve_id", cve_id)
    _seed_node(driver, "ThreatActor", "merge_key", actor_key)

    article_id = f"{_TEST_PREFIX}::article-cache"
    cluster_id = f"{_TEST_PREFIX}::cluster-cache"
    content_hash = "hash-cache-hit"
    _seed_article(driver, article_id, cluster_id, "APT was seen exploiting the CVE.", content_hash)

    entities = [
        ResolvedEntity(cve_id, "cve", "resolved", 1.0),
        ResolvedEntity(actor_key, "threat_actor", "resolved", 0.9),
    ]
    story_cluster = StoryCluster(
        story_cluster_id=cluster_id, article_ids=[article_id], union_resolved_entities=entities
    )

    candidate = CandidateRelation(
        entity_a={"canonical_node_key": actor_key, "entity_type": "threat_actor"},
        entity_b={"canonical_node_key": cve_id, "entity_type": "cve"},
        relationship="exploits",
        direction="b_to_a",
        assertion_strength=0.9,
        polarity="asserted",
    )
    from src.nlp.inference.re_cache import put_cached_result

    put_cached_result(re_cache_table, content_hash, [candidate])

    with patch("src.nlp.inference.handler.extract_relations") as mock_extract:
        _process_story_cluster(
            story_cluster.to_dict(), driver, re_cache_table, _no_llm_needed
        )
        mock_extract.assert_not_called()

    assert _edge_exists(
        driver, "CVE", "cve_id", cve_id, "EXPLOITED_BY", "ThreatActor", "merge_key", actor_key
    )


@patch("src.nlp.inference.handler.publish_graph_write")
def test_entities_only_co_occurring_across_separate_clusters_get_no_edge(
    mock_publish, driver, re_cache_table
):
    # FR-INF-08: structural by construction -- extract_relations is only ever called
    # with one cluster's own text/entities, so two entities that only ever co-occur in
    # *different* clusters can never have a candidate relationship proposed between
    # them in the first place. Proven here by processing two single-article clusters
    # independently and confirming no edge was ever created between the two malware
    # families that never appeared together in any one cluster's entity list.
    actor_key = "apt-cross-cluster-test"
    malware_m = "malware-m-cross-cluster-test"
    malware_n = "malware-n-cross-cluster-test"
    _seed_node(driver, "ThreatActor", "merge_key", actor_key)
    _seed_node(driver, "MalwareFamily", "merge_key", malware_m)
    _seed_node(driver, "MalwareFamily", "merge_key", malware_n)

    article_1 = f"{_TEST_PREFIX}::cross-article-1"
    cluster_1 = f"{_TEST_PREFIX}::cross-cluster-1"
    _seed_article(driver, article_1, cluster_1, "APT used malware M.", "hash-cross-1")

    article_2 = f"{_TEST_PREFIX}::cross-article-2"
    cluster_2 = f"{_TEST_PREFIX}::cross-cluster-2"
    _seed_article(driver, article_2, cluster_2, "APT used malware N.", "hash-cross-2")

    cluster_1_entities = [
        ResolvedEntity(actor_key, "threat_actor", "resolved", 0.9),
        ResolvedEntity(malware_m, "malware_family", "resolved", 0.9),
    ]
    cluster_2_entities = [
        ResolvedEntity(actor_key, "threat_actor", "resolved", 0.9),
        ResolvedEntity(malware_n, "malware_family", "resolved", 0.9),
    ]

    story_cluster_1 = StoryCluster(
        story_cluster_id=cluster_1, article_ids=[article_1], union_resolved_entities=cluster_1_entities
    )
    story_cluster_2 = StoryCluster(
        story_cluster_id=cluster_2, article_ids=[article_2], union_resolved_entities=cluster_2_entities
    )

    candidate_1 = CandidateRelation(
        entity_a={"canonical_node_key": actor_key, "entity_type": "threat_actor"},
        entity_b={"canonical_node_key": malware_m, "entity_type": "malware_family"},
        relationship="uses",
        direction="a_to_b",
        assertion_strength=0.8,
        polarity="asserted",
    )
    candidate_2 = CandidateRelation(
        entity_a={"canonical_node_key": actor_key, "entity_type": "threat_actor"},
        entity_b={"canonical_node_key": malware_n, "entity_type": "malware_family"},
        relationship="uses",
        direction="a_to_b",
        assertion_strength=0.8,
        polarity="asserted",
    )

    with patch(
        "src.nlp.inference.handler.extract_relations", side_effect=[[candidate_1], [candidate_2]]
    ):
        _process_story_cluster(story_cluster_1.to_dict(), driver, re_cache_table, _unused_llm_client)
        _process_story_cluster(story_cluster_2.to_dict(), driver, re_cache_table, _unused_llm_client)

    # Each cluster's own USES edge was written...
    assert _edge_exists(
        driver, "ThreatActor", "merge_key", actor_key, "USES", "MalwareFamily", "merge_key", malware_m
    )
    assert _edge_exists(
        driver, "ThreatActor", "merge_key", actor_key, "USES", "MalwareFamily", "merge_key", malware_n
    )
    # ...but malware_m and malware_n, which only ever co-occurred across the two
    # separate clusters (never together in one cluster's entity list), have no edge
    # of any kind between them -- no candidate relationship between them could ever
    # have been proposed, by construction.
    with driver.session() as s:
        cross_edge = s.run(
            "MATCH (:MalwareFamily {merge_key: $m})-[r]-(:MalwareFamily {merge_key: $n}) RETURN r",
            m=malware_m,
            n=malware_n,
        ).single()
    assert cross_edge is None
