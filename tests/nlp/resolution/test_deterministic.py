import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.nlp.messages import RawMention
from src.nlp.resolution.deterministic import resolve_cve, resolve_ioc, resolve_ttp

ARTICLE_ID = "resolution-test-source::resolution-test-guid"


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
def article(driver):
    with driver.session() as s:
        s.run(
            "MERGE (a:Article {source_guid_key: $key}) "
            "SET a.test_fixture = true, a.source_id = 'resolution-test-source', "
            "a.guid = 'resolution-test-guid'",
            key=ARTICLE_ID,
        ).consume()
    return driver


def _mark_test_fixture(driver, label: str, key_prop: str, key_value: str) -> None:
    with driver.session() as s:
        s.run(
            f"MATCH (n:{label} {{{key_prop}: $value}}) SET n.test_fixture = true",
            value=key_value,
        ).consume()


def _mention(entity_type: str, surface_text: str, confidence: float = 0.9) -> RawMention:
    return RawMention(
        article_id=ARTICLE_ID,
        entity_type=entity_type,
        surface_text=surface_text,
        char_span=(0, len(surface_text)),
        extraction_confidence=confidence,
        context_snippet=f"...{surface_text}...",
    )


# FR-RES-01: un-ingested CVE mention -> CVE node exists + enrichment_pending=true
def test_resolve_cve_lazy_creates_stub_with_enrichment_pending(article):
    mention = _mention("cve", "CVE-2099-00001")

    result = resolve_cve(article, mention)
    _mark_test_fixture(article, "CVE", "cve_id", "CVE-2099-00001")

    assert result.canonical_node_key == "CVE-2099-00001"
    assert result.resolution_status == "resolved"
    with article.session() as s:
        record = s.run(
            "MATCH (c:CVE {cve_id: 'CVE-2099-00001'}) RETURN c.enrichment_pending AS pending"
        ).single()
    assert record is not None
    assert record["pending"] is True


# FR-RES-07: resolved mention gets a MENTIONS edge
def test_resolve_cve_writes_mentions_edge(article):
    mention = _mention("cve", "CVE-2099-00002")

    resolve_cve(article, mention)
    _mark_test_fixture(article, "CVE", "cve_id", "CVE-2099-00002")

    with article.session() as s:
        count = s.run(
            "MATCH (:Article {source_guid_key: $key})-[r:MENTIONS]->"
            "(:CVE {cve_id: 'CVE-2099-00002'}) RETURN count(r) AS c",
            key=ARTICLE_ID,
        ).single()["c"]
    assert count == 1


# FR-RES-03: unknown TTP id -> no node, mention rejected
def test_resolve_ttp_unknown_id_is_rejected_no_node_created(article):
    mention = _mention("ttp", "T9999")

    result = resolve_ttp(article, mention)

    assert result.resolution_status == "rejected"
    with article.session() as s:
        count = s.run("MATCH (t:TTP {technique_id: 'T9999'}) RETURN count(t) AS c").single()["c"]
    assert count == 0


# FR-RES-07: rejected mention -> no MENTIONS edge exists
def test_resolve_ttp_unknown_id_writes_no_mentions_edge(article):
    mention = _mention("ttp", "T9999")

    resolve_ttp(article, mention)

    with article.session() as s:
        count = s.run(
            "MATCH (:Article {source_guid_key: $key})-[r:MENTIONS]->(:TTP) RETURN count(r) AS c",
            key=ARTICLE_ID,
        ).single()["c"]
    assert count == 0


def test_resolve_ttp_known_id_matches_existing_node_and_writes_mentions_edge(article):
    with article.session() as s:
        s.run(
            "MERGE (t:TTP {technique_id: 'T1566'}) SET t.test_fixture = true"
        ).consume()
    mention = _mention("ttp", "T1566")

    result = resolve_ttp(article, mention)

    assert result.canonical_node_key == "T1566"
    assert result.resolution_status == "resolved"
    with article.session() as s:
        count = s.run(
            "MATCH (:Article {source_guid_key: $key})-[r:MENTIONS]->"
            "(:TTP {technique_id: 'T1566'}) RETURN count(r) AS c",
            key=ARTICLE_ID,
        ).single()["c"]
    assert count == 1


# FR-RES-04: new IOC -> node keyed on value_type_key = ioc_key(value, ioc_type),
# confidence = mention's extraction_confidence
def test_resolve_ioc_creates_node_keyed_on_value_type_key_with_mention_confidence(article):
    mention = _mention("ioc", "203.0.113.77", confidence=0.42)

    result = resolve_ioc(article, mention)
    with article.session() as s:
        s.run(
            "MATCH (i:IOC {value_type_key: $key}) SET i.test_fixture = true",
            key=result.canonical_node_key,
        ).consume()

    assert result.canonical_node_key == "203.0.113.77::ipv4"
    assert result.resolution_status == "resolved"
    with article.session() as s:
        record = s.run(
            "MATCH (i:IOC {value_type_key: '203.0.113.77::ipv4'}) "
            "RETURN i.confidence AS confidence, i.value AS value, i.ioc_type AS ioc_type"
        ).single()
    assert record["confidence"] == 0.42
    assert record["value"] == "203.0.113.77"
    assert record["ioc_type"] == "ipv4"


def test_resolve_ioc_writes_mentions_edge(article):
    mention = _mention("ioc", "203.0.113.88", confidence=0.5)

    result = resolve_ioc(article, mention)
    with article.session() as s:
        s.run(
            "MATCH (i:IOC {value_type_key: $key}) SET i.test_fixture = true",
            key=result.canonical_node_key,
        ).consume()

    with article.session() as s:
        count = s.run(
            "MATCH (:Article {source_guid_key: $key})-[r:MENTIONS]->"
            "(:IOC {value_type_key: '203.0.113.88::ipv4'}) RETURN count(r) AS c",
            key=ARTICLE_ID,
        ).single()["c"]
    assert count == 1
