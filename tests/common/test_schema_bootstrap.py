import pytest
from neo4j import GraphDatabase

from src.common.schema_bootstrap import bootstrap_schema

NEO4J_URI = "bolt://localhost:7687"
NEO4J_AUTH = ("neo4j", "crossroads-dev")


@pytest.fixture
def driver():
    d = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
    d.verify_connectivity()
    with d.session() as session:
        session.run("SHOW CONSTRAINTS YIELD name RETURN name").consume()
        for record in session.run("SHOW CONSTRAINTS YIELD name"):
            session.run(f"DROP CONSTRAINT {record['name']}")
        for record in session.run("SHOW INDEXES YIELD name, type WHERE type = 'VECTOR'"):
            session.run(f"DROP INDEX {record['name']}")
    yield d
    d.close()


def test_bootstrap_creates_all_constraints_and_the_vector_index(driver):
    applied = bootstrap_schema(driver)

    assert set(applied) == {
        "source_url_unique",
        "cve_id_unique",
        "cwe_id_unique",
        "ttp_technique_id_unique",
        "threat_actor_merge_key_unique",
        "malware_family_merge_key_unique",
        "campaign_merge_key_unique",
        "article_source_guid_key",
        "ioc_value_type_key",
        "cpe_match_id_unique",
        "asset_key_unique",
        # Range indexes backing the asset matcher (final-review finding #4): without
        # them every match event and sweep page planned a full label scan over CPEMatch.
        "cpe_match_vendor_product_index",
        "cpe_match_vendor_index",
        "cpe_match_product_index",
        "asset_vendor_product_index",
        "article_embedding_index",
    }

    with driver.session() as session:
        names = {r["name"] for r in session.run("SHOW CONSTRAINTS YIELD name")}
        assert "source_url_unique" in names
        assert "article_source_guid_key" in names

        index_names = {r["name"] for r in session.run("SHOW INDEXES YIELD name")}
        assert "article_embedding_index" in index_names
        assert "cpe_match_vendor_product_index" in index_names
        assert "asset_vendor_product_index" in index_names


def test_bootstrap_is_idempotent(driver):
    bootstrap_schema(driver)
    second_run_applied = bootstrap_schema(driver)  # must not raise
    assert len(second_run_applied) == 16
