from datetime import datetime, timedelta, timezone

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.scoring.confidence import decay_edges_batch

NOW = datetime(2026, 7, 30, tzinfo=timezone.utc)


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


def _seed_edge(driver, *, origin, inferred, authoritative, days_ago):
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-7001'}) SET c.test_fixture = true "
            "MERGE (a:ThreatActor {merge_key:'apt-decay-test'}) SET a.test_fixture = true "
            "MERGE (c)-[r:EXPLOITED_BY]->(a) "
            "SET r.origin = $origin, r.inferred_confidence = $inferred, "
            "    r.authoritative_confidence = $authoritative, "
            "    r.confidence = $inferred, r.last_confirmed = $lc",
            origin=origin, inferred=inferred, authoritative=authoritative,
            lc=NOW - timedelta(days=days_ago),
        ).consume()


def _seed_edge_never_confirmed(driver, *, origin, inferred, authoritative):
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-7001'}) SET c.test_fixture = true "
            "MERGE (a:ThreatActor {merge_key:'apt-decay-test'}) SET a.test_fixture = true "
            "MERGE (c)-[r:EXPLOITED_BY]->(a) "
            "SET r.origin = $origin, r.inferred_confidence = $inferred, "
            "    r.authoritative_confidence = $authoritative, "
            "    r.confidence = $inferred "
            "REMOVE r.last_confirmed",
            origin=origin, inferred=inferred, authoritative=authoritative,
        ).consume()


def _run(driver):
    with driver.session() as s:
        return s.execute_write(
            lambda tx: decay_edges_batch(
                tx, cursor=None, batch_size=100, halflife_days=180.0, now=NOW
            )
        )


def _confidence(driver):
    with driver.session() as s:
        return s.run(
            "MATCH ()-[r:EXPLOITED_BY]->(:ThreatActor {merge_key:'apt-decay-test'}) "
            "RETURN r.confidence AS c, r.inferred_confidence AS ic"
        ).single()


def test_inferred_edge_decays_by_a_true_halflife(driver):
    _seed_edge(driver, origin=["inferred"], inferred=0.8, authoritative=0.0, days_ago=180)
    _run(driver)
    assert _confidence(driver)["c"] == pytest.approx(0.4)


def test_the_immutable_base_is_never_written(driver):
    """FR-ES-09 rests entirely on this: decay reads inferred_confidence, never writes it."""
    _seed_edge(driver, origin=["inferred"], inferred=0.8, authoritative=0.0, days_ago=180)
    _run(driver)
    assert _confidence(driver)["ic"] == pytest.approx(0.8)


def test_fr_es_09_running_twice_in_one_day_is_idempotent(driver):
    """FR-ES-09: Given the decay sweep runs twice in one day, When compared, Then the
    edge's effective confidence is identical."""
    _seed_edge(driver, origin=["inferred"], inferred=0.8, authoritative=0.0, days_ago=90)
    _run(driver)
    once = _confidence(driver)["c"]
    _run(driver)
    assert _confidence(driver)["c"] == once


def test_fr_es_09_authoritative_edges_do_not_decay(driver):
    """FR-ES-09: any feed-backed edge is unchanged."""
    _seed_edge(
        driver, origin=["authoritative"], inferred=0.0, authoritative=1.0, days_ago=10_000
    )
    _run(driver)
    assert _confidence(driver)["c"] == 1.0


def test_a_mixed_edge_is_pinned_at_the_feed_credibility(driver):
    _seed_edge(
        driver, origin=["authoritative", "inferred"],
        inferred=0.8, authoritative=0.9, days_ago=10_000,
    )
    _run(driver)
    assert _confidence(driver)["c"] == pytest.approx(0.9)


def test_a_naive_last_confirmed_is_treated_as_utc(driver):
    """last_confirmed can be written as a naive datetime elsewhere in the codebase
    (assertion_edges.py takes a caller-supplied `now: datetime` with no tz enforced);
    decay must not crash comparing a naive stored value against an aware `now`."""
    naive_180_days_ago = (NOW - timedelta(days=180)).replace(tzinfo=None)
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-7001'}) SET c.test_fixture = true "
            "MERGE (a:ThreatActor {merge_key:'apt-decay-test'}) SET a.test_fixture = true "
            "MERGE (c)-[r:EXPLOITED_BY]->(a) "
            "SET r.origin = ['inferred'], r.inferred_confidence = 0.8, "
            "    r.authoritative_confidence = 0.0, r.confidence = 0.8, "
            "    r.last_confirmed = $lc",
            lc=naive_180_days_ago,
        ).consume()
    _run(driver)
    assert _confidence(driver)["c"] == pytest.approx(0.4)


def test_an_edge_never_confirmed_passes_through_undecayed(driver):
    """No last_confirmed means no elapsed time to decay over (formulas.decay's contract)."""
    _seed_edge_never_confirmed(driver, origin=["inferred"], inferred=0.8, authoritative=0.0)
    _run(driver)
    assert _confidence(driver)["c"] == pytest.approx(0.8)


def test_pagination_exhausts_and_terminates(driver):
    _seed_edge(driver, origin=["inferred"], inferred=0.8, authoritative=0.0, days_ago=10)
    _, cursor = _run(driver)
    with driver.session() as s:
        _, next_cursor = s.execute_write(
            lambda tx: decay_edges_batch(
                tx, cursor=cursor, batch_size=100, halflife_days=180.0, now=NOW
            )
        )
    assert next_cursor is None
