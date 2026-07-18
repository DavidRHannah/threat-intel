from datetime import datetime, timezone

import pytest

from src.common.graph.assertion_edges import upsert_authoritative_assertion
from src.common.graph.recompute import recompute_confidence_for_feed
from src.common.neo4j_driver import close_driver, get_driver


@pytest.fixture
def driver():
    # Use the get_driver() singleton, not a hand-rolled GraphDatabase.driver: it is what
    # L1/L2 call in production, and it keeps connection config in src/common/config.py
    # rather than duplicated across every L3 test file (§2).
    d = get_driver()
    d.verify_connectivity()
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-0006'}) SET c.test_fixture = true "
            "MERGE (a:ThreatActor {merge_key:'apt-recompute-test'}) SET a.test_fixture = true "
            # The recompute joins feed_sources -> Source.source_id, so the Source nodes
            # must exist. url is the natural key; source_id is the join key.
            "MERGE (s1:Source {url:'https://otx.example/feed'}) "
            "  SET s1.source_id='otx', s1.credibility_score=0.6, s1.test_fixture = true "
            "MERGE (s2:Source {url:'https://mitre.example/feed'}) "
            "  SET s2.source_id='mitre-attack', s2.credibility_score=1.0, s2.test_fixture = true"
        ).consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


def test_recompute_applies_new_credibility_to_affected_edges(driver):
    now = datetime.now(timezone.utc)
    with driver.session() as s:
        s.execute_write(lambda tx: upsert_authoritative_assertion(
            tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0006"},
            end_label="ThreatActor", end_key={"merge_key": "apt-recompute-test"},
            rel_type="EXPLOITED_BY", feed_source="otx", credibility_score=0.6, now=now,
        ))
        touched = s.execute_write(lambda tx: recompute_confidence_for_feed(
            tx, feed_source="otx", new_credibility_score=0.75
        ))
        conf = s.run(
            "MATCH (:CVE {cve_id:'CVE-2026-0006'})-[r:EXPLOITED_BY]->"
            "(:ThreatActor {merge_key:'apt-recompute-test'}) RETURN r.confidence AS c"
        ).single()["c"]
    assert touched == 1
    assert conf == 0.75


def test_recompute_does_not_drop_a_co_asserting_feeds_credibility(driver):
    # An edge asserted by BOTH mitre-attack (1.0) and otx (0.6). Editing otx must not
    # downgrade the edge to otx's score -- confidence is the max over ALL contributing
    # feeds. A recompute that only considers the changed feed yields 0.5 here.
    now = datetime.now(timezone.utc)
    with driver.session() as s:
        for feed, cred in (("otx", 0.6), ("mitre-attack", 1.0)):
            s.execute_write(lambda tx, f=feed, c=cred: upsert_authoritative_assertion(
                tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0006"},
                end_label="ThreatActor", end_key={"merge_key": "apt-recompute-test"},
                rel_type="EXPLOITED_BY", feed_source=f, credibility_score=c, now=now,
            ))
        s.execute_write(lambda tx: recompute_confidence_for_feed(
            tx, feed_source="otx", new_credibility_score=0.5
        ))
        r = s.run(
            "MATCH (:CVE {cve_id:'CVE-2026-0006'})-[r:EXPLOITED_BY]->"
            "(:ThreatActor {merge_key:'apt-recompute-test'}) RETURN r AS r"
        ).single()["r"]
    assert sorted(r["feed_sources"]) == ["mitre-attack", "otx"]
    assert r["confidence"] == 1.0  # mitre-attack still contributes 1.0
    assert r["authoritative_confidence"] == 1.0


def test_recompute_applies_when_the_feeds_source_node_is_absent(driver):
    # feed_sources can name a Source with no node in the graph -- config-sync syncs
    # removals, and the changed feed's node may not be written yet. A plain
    # `MATCH (s:Source)` is an inner join: it would drop the row and SILENTLY SKIP the
    # edge this recompute was called for, under-reporting `touched`. OPTIONAL MATCH is
    # what makes this pass.
    now = datetime.now(timezone.utc)
    with driver.session() as s:
        s.execute_write(lambda tx: upsert_authoritative_assertion(
            tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0006"},
            end_label="ThreatActor", end_key={"merge_key": "apt-recompute-test"},
            rel_type="EXPLOITED_BY", feed_source="ghost-feed", credibility_score=0.3,
            now=now,
        ))
        touched = s.execute_write(lambda tx: recompute_confidence_for_feed(
            tx, feed_source="ghost-feed", new_credibility_score=0.85
        ))
        conf = s.run(
            "MATCH (:CVE {cve_id:'CVE-2026-0006'})-[r:EXPLOITED_BY]->"
            "(:ThreatActor {merge_key:'apt-recompute-test'}) "
            "WHERE 'ghost-feed' IN r.feed_sources RETURN r.confidence AS c"
        ).single()["c"]
    assert touched == 1  # not 0: the edge must not be skipped
    assert conf == 0.85
