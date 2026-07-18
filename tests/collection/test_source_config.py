# FR-DC-16: git-tracked config/sources.yaml is the source of truth for feeds; sync_sources
# reconciles it into DynamoDB (deleted when removed) and Neo4j (flagged inactive, never deleted).
import pytest
from neo4j import GraphDatabase
from src.collection.source_config import sync_sources

NEO4J_URI = "bolt://localhost:7687"
NEO4J_AUTH = ("neo4j", "crossroads-dev")

@pytest.fixture
def driver():
    d = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
    d.verify_connectivity()
    with d.session() as s:
        s.run("MATCH (n:Source) DETACH DELETE n").consume()
    yield d
    d.close()

class _FakeTable:
    def __init__(self):
        self.items = {}
    def put_item(self, Item):
        self.items[Item["source_id"]] = Item
    def scan(self):
        return {"Items": list(self.items.values())}
    def delete_item(self, Key):
        self.items.pop(Key["source_id"], None)

def test_sync_creates_source_nodes_and_dynamodb_rows(tmp_path, driver):
    config_path = tmp_path / "sources.yaml"
    config_path.write_text(
        "- source_id: krebs\n"
        "  name: Krebs on Security\n"
        "  url: https://krebsonsecurity.com/feed/\n"
        "  type: rss\n"
        "  category: osint\n"
        "  credibility_score: 0.9\n"
        "  polling_tier: standard\n"
    )
    table = _FakeTable()

    result = sync_sources(str(config_path), table, driver)

    assert result.created == 1
    assert table.items["krebs"]["url"] == "https://krebsonsecurity.com/feed/"
    with driver.session() as s:
        rec = s.run(
            "MATCH (s:Source {url: $url}) RETURN s.source_id AS id, s.is_active AS active",
            url="https://krebsonsecurity.com/feed/",
        ).single()
        assert rec["id"] == "krebs"
        assert rec["active"] is True

def test_sync_deactivates_removed_sources_in_neo4j_but_deletes_from_dynamodb(tmp_path, driver):
    config_path = tmp_path / "sources.yaml"
    config_path.write_text("[]\n")
    table = _FakeTable()
    table.put_item(Item={"source_id": "old-src", "url": "https://old.example/feed"})
    with driver.session() as s:
        s.run(
            "MERGE (src:Source {url: $url}) SET src.source_id = $id, src.is_active = true",
            url="https://old.example/feed", id="old-src",
        ).consume()

    result = sync_sources(str(config_path), table, driver)

    assert result.deactivated == 1
    assert "old-src" not in table.items
    with driver.session() as s:
        rec = s.run(
            "MATCH (s:Source {source_id: 'old-src'}) RETURN s.is_active AS active"
        ).single()
        assert rec["active"] is False
