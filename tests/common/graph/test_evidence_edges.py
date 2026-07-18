from datetime import datetime, timezone

import pytest
from neo4j.exceptions import ConstraintError

from src.common import natural_keys
from src.common.graph.evidence_edges import write_mentions_edge, write_published_by_edge
from src.common.neo4j_driver import close_driver, get_driver
from src.common.schema_bootstrap import bootstrap_schema

ARTICLE_REF = {"source_id": "src-1", "guid": "guid-1"}
ARTICLE_KEY = natural_keys.article_key(**ARTICLE_REF)


@pytest.fixture
def driver():
    # Use the get_driver() singleton, not a hand-rolled GraphDatabase.driver: it is what
    # L1/L2 call in production, and it keeps connection config in src/common/config.py
    # rather than duplicated across every L3 test file (§2).
    d = get_driver()
    d.verify_connectivity()
    bootstrap_schema(d)
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
        # The fixture Article MUST be merged on source_guid_key — the property the UNIQUE
        # constraint is on. Merging on the raw (source_id, guid) pair leaves source_guid_key
        # null, and Neo4j UNIQUE constraints ignore nulls, so the test would pass against a
        # node the schema does not actually constrain.
        s.run(
            "MERGE (a:Article {source_guid_key: $article_key}) "
            "SET a.source_id = $source_id, a.guid = $guid, a.test_fixture = true "
            "MERGE (c:CVE {cve_id:'CVE-2026-0003'}) SET c.test_fixture = true",
            article_key=ARTICLE_KEY, **ARTICLE_REF,
        ).consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


def test_mentions_edge_carries_required_properties(driver):
    now = datetime.now(timezone.utc)
    with driver.session() as s:
        s.execute_write(lambda tx: write_mentions_edge(
            tx, article_ref=ARTICLE_REF,
            entity_label="CVE", entity_key={"cve_id": "CVE-2026-0003"},
            extraction_confidence=0.9, extracted_at=now, context_snippet="exploited via CVE-2026-0003",
        ))
        r = s.run(
            "MATCH (:Article {source_guid_key: $article_key})-[r:MENTIONS]->"
            "(:CVE {cve_id:'CVE-2026-0003'}) RETURN r AS r",
            article_key=ARTICLE_KEY,
        ).single()["r"]
    assert r["extraction_confidence"] == 0.9  # FR-RG-07
    assert r["extracted_at"] is not None
    assert r["context_snippet"] == "exploited via CVE-2026-0003"


def test_duplicate_article_source_guid_key_raises_constraint_error(driver):
    # NFR-DATA-01: Article's composite natural key (source_id, guid) is not enforced directly
    # (NODE KEY is Enterprise-only, unavailable on AuraDB Free). It is enforced via a single
    # synthetic property, source_guid_key = natural_keys.article_key(source_id, guid), backed by
    # a single-property UNIQUE constraint (src/common/schema_bootstrap.py). UNIQUE constraints
    # ignore nulls, so a writer that fails to set source_guid_key would get zero enforcement
    # silently. This test proves the constraint is actually live: creating a second Article node
    # with the same source_guid_key (but a distinct elementId — a plain CREATE, not a MERGE) must
    # raise neo4j.exceptions.ConstraintError.
    with driver.session() as s:
        with pytest.raises(ConstraintError):
            s.run(
                "CREATE (a:Article {source_guid_key: $article_key, test_fixture: true})",
                article_key=ARTICLE_KEY,
            ).consume()


def test_published_by_edge_is_unchanged_on_reprocess(driver):
    with driver.session() as s:
        s.run("MERGE (src:Source {url:'https://example.test/feed'}) SET src.test_fixture = true").consume()
        s.execute_write(lambda tx: write_published_by_edge(
            tx, article_ref=ARTICLE_REF,
            source_key={"url": "https://example.test/feed"},
        ))
        s.execute_write(lambda tx: write_published_by_edge(
            tx, article_ref=ARTICLE_REF,
            source_key={"url": "https://example.test/feed"},
        ))
        count = s.run(
            "MATCH (:Article {source_guid_key: $article_key})-[r:PUBLISHED_BY]->"
            "(:Source {url:'https://example.test/feed'}) RETURN count(r) AS c",
            article_key=ARTICLE_KEY,
        ).single()["c"]
    assert count == 1  # FR-RG-08
