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

def test_sync_missing_required_field_raises_value_error(tmp_path):
    config_path = tmp_path / "sources.yaml"
    config_path.write_text(
        "- source_id: krebs\n"
        "  name: Krebs on Security\n"
        "  url: https://krebsonsecurity.com/feed/\n"
        "  type: rss\n"
        "  category: osint\n"
        "  polling_tier: standard\n"
    )
    table = _FakeTable()

    with pytest.raises(ValueError, match="credibility_score"):
        sync_sources(str(config_path), table, driver=None)

def test_sync_second_run_deactivates_zero(tmp_path, driver):
    # No DynamoDB row for old-src, so the DynamoDB delete count is always 0 for this
    # source; this isolates the Neo4j deactivation count (must be a true per-run delta,
    # not a re-flag of every historically-removed source on every run).
    config_path = tmp_path / "sources.yaml"
    config_path.write_text("[]\n")
    table = _FakeTable()
    with driver.session() as s:
        s.run(
            "MERGE (src:Source {url: $url}) SET src.source_id = $id, src.is_active = true",
            url="https://old.example/feed", id="old-src",
        ).consume()

    first = sync_sources(str(config_path), table, driver)
    second = sync_sources(str(config_path), table, driver)

    assert first.deactivated == 1
    assert second.deactivated == 0

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


def test_api_source_ids_match_the_ids_collectors_actually_use():
    """FR-DC-16: the shipped config's ids must match the collectors' own ids.

    `read_source_credibility_score` (rest/normalizer.py) looks up
    `Source {source_id: <collector's id>}`. If config/sources.yaml registers a
    different id, that lookup silently misses and every authoritative write falls
    back to DEFAULT_SOURCE_CREDIBILITY_SCORE, so the configured credibility_score
    never applies. Nothing else pins these two vocabularies together.
    """
    from pathlib import Path

    import yaml

    from src.collection.rest.abusech import (
        MALWAREBAZAAR_SOURCE_ID,
        THREATFOX_SOURCE_ID,
        URLHAUS_SOURCE_ID,
    )
    from src.collection.rest.cisa_kev import SOURCE_ID as CISA_KEV_SOURCE_ID
    from src.collection.rest.ghsa import SOURCE_ID as GHSA_SOURCE_ID
    from src.collection.rest.nvd import _NVD_SOURCE_ID
    from src.collection.rest.otx import SOURCE_ID as OTX_SOURCE_ID
    from src.collection.stix.attck_sync import _ATTCK_SOURCE_ID

    collector_ids = {
        OTX_SOURCE_ID, GHSA_SOURCE_ID, CISA_KEV_SOURCE_ID, _NVD_SOURCE_ID,
        _ATTCK_SOURCE_ID, URLHAUS_SOURCE_ID, MALWAREBAZAAR_SOURCE_ID, THREATFOX_SOURCE_ID,
    }

    config_path = Path(__file__).parents[2] / "config" / "sources.yaml"
    entries = yaml.safe_load(config_path.read_text())
    api_ids = {e["source_id"] for e in entries if e["type"] == "api"}

    unmatched = api_ids - collector_ids
    assert not unmatched, (
        f"config/sources.yaml registers api source ids no collector uses: {sorted(unmatched)}. "
        f"Collector ids are {sorted(collector_ids)}."
    )


def test_plan_sync_reports_deletions_without_performing_them(tmp_path):
    """A destructive sync must be previewable: `sync_sources` DELETES DynamoDB rows whose
    source_id is absent from the config, which silently orphans the provenance of every
    Article already carrying that id. plan_sync is the read-only preview.
    """
    from src.collection.source_config import plan_sync

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
    table.put_item(Item={"source_id": "doomed-src", "url": "https://old.example/feed"})

    plan = plan_sync(str(config_path), table)

    assert plan.to_create == ["krebs"]
    assert plan.to_delete == ["doomed-src"]
    assert plan.to_update == []
    # The row must still be there -- planning is read-only.
    assert "doomed-src" in table.items


def test_sync_writes_credibility_score_as_decimal_not_float(tmp_path, driver):
    """Real DynamoDB rejects Python floats ("Float types are not supported").

    credibility_score is a float in YAML, and every existing test uses a dict-backed
    fake table that accepts floats happily -- so sync_sources raised TypeError the
    first time it ever ran against real DynamoDB.
    """
    from decimal import Decimal

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

    sync_sources(str(config_path), table, driver)

    written = table.items["krebs"]["credibility_score"]
    assert isinstance(written, Decimal), f"got {type(written).__name__}: {written!r}"
    assert written == Decimal("0.9")
