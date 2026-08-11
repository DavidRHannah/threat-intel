"""The daily sweep (FR-ES-07, FR-ES-08, FR-ES-10).

Integration tests against real Neo4j: every phase is Cypher, and the properties that
matter here -- termination, idempotency, flags that clear -- are properties of the
queries, not of the Python around them.
"""

import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.scoring.confidence import (
    refine_from_mention,
    refine_provisional_confidence,
    rescan_confidence_batch,
)
from src.scoring.formulas import noisy_or
from src.scoring.sweep_handler import PHASES, handler

NOW = datetime(2026, 7, 30, tzinfo=timezone.utc)


@pytest.fixture
def batch_size_one(monkeypatch):
    """Force one row per page, so a multi-page drain is the only way to finish.

    A stuck cursor does not hang: it reports `done` after page one and silently skips
    every later row. Only a batch smaller than the seeded set can tell the two apart.
    """
    from src.common.config import get_config

    monkeypatch.setenv("CROSSROADS_SWEEP_BATCH_SIZE", "1")
    get_config.cache_clear()
    yield
    get_config.cache_clear()


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


def _drain(phase, max_pages=20):
    """Drive one sweep phase to exhaustion, exactly as the Step Function loop does.

    Raising when the page budget runs out is the real termination check: a cursor that
    fails to advance makes the Step Function loop forever.
    """
    cursor, pages, total = None, 0, 0
    while pages < max_pages:
        out = handler({"phase": phase, "cursor": cursor}, None)
        total += out["count"]
        pages += 1
        if out["done"]:
            return total, pages, out
        cursor = out["cursor"]
    raise AssertionError(f"{phase} did not terminate in {max_pages} pages")


def test_fr_es_07_novelty_is_recomputed_with_no_events(driver):
    """FR-ES-07: Given a day passes with no events, When the sweep runs, Then novelty
    and edge decay are recomputed."""
    with driver.session() as s:
        s.run(
            "MERGE (a:ThreatActor {merge_key:'apt-sweep-test'}) "
            "SET a.test_fixture = true, a.first_seen = $old, a.relevance_score = 1.0",
            old=NOW - timedelta(days=70),
        ).consume()

    _drain("novelty")

    with driver.session() as s:
        score = s.run(
            "MATCH (a:ThreatActor {merge_key:'apt-sweep-test'}) "
            "RETURN a.relevance_score AS s"
        ).single()["s"]
    assert score < 1.0


def test_severity_rescan_covers_a_kev_cve_with_no_cvss(driver):
    """Spec §4: the rescan predicate is `cvss_score IS NOT NULL OR exploited_in_wild`."""
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-9101'}) "
            "SET c.test_fixture = true, c.exploited_in_wild = true"
        ).consume()

    _drain("severity_rescan")

    with driver.session() as s:
        band = s.run(
            "MATCH (c:CVE {cve_id:'CVE-2026-9101'}) RETURN c.severity_band AS b"
        ).single()["b"]
    assert band == "high"


def test_fr_es_10_stale_low_confidence_provisional_node_is_flagged(driver):
    with driver.session() as s:
        s.run(
            "MERGE (a:ThreatActor:Provisional {merge_key:'apt-prune-test'}) "
            "SET a.test_fixture = true, a.confidence = 0.05, a.first_seen = $old",
            old=NOW - timedelta(days=365),
        ).consume()

    _drain("prune_flags")

    with driver.session() as s:
        node = s.run(
            "MATCH (a:ThreatActor {merge_key:'apt-prune-test'}) RETURN a AS a"
        ).single()["a"]
    assert node["prune_candidate"] is True
    assert node["prune_reason"] == "stale_low_confidence_provisional"


def test_fr_es_10_flags_are_cleared_when_no_longer_applicable(driver):
    """A flag that only turns on is a ratchet, not an idempotent recompute."""
    with driver.session() as s:
        s.run(
            "MERGE (a:ThreatActor:Provisional {merge_key:'apt-prune-test'}) "
            "SET a.test_fixture = true, a.confidence = 0.05, a.first_seen = $old, "
            "    a.prune_candidate = true",
            old=NOW - timedelta(days=365),
        ).consume()
        s.run(
            "MATCH (a:ThreatActor {merge_key:'apt-prune-test'}) SET a.confidence = 0.95"
        ).consume()

    _drain("prune_flags")

    with driver.session() as s:
        node = s.run(
            "MATCH (a:ThreatActor {merge_key:'apt-prune-test'}) RETURN a AS a"
        ).single()["a"]
    assert node["prune_candidate"] is False


def test_a_malformed_first_seen_does_not_stall_the_prune_scan(driver):
    """duration.inSeconds RAISES on a string, which would abort the page's transaction
    and re-read the same node forever. The `IS :: ZONED DATETIME` guard is what keeps one
    malformed node from stalling the whole sweep."""
    with driver.session() as s:
        s.run(
            "MERGE (a:ThreatActor:Provisional {merge_key:'apt-bad-clock'}) "
            "SET a.test_fixture = true, a.confidence = 0.05, "
            "    a.first_seen = '2026-07-20 09:00:00'"
        ).consume()

    _drain("prune_flags")

    with driver.session() as s:
        node = s.run(
            "MATCH (a:ThreatActor {merge_key:'apt-bad-clock'}) RETURN a AS a"
        ).single()["a"]
    # Unusable clock -> cannot establish staleness -> not flagged, and no exception.
    assert node["prune_candidate"] is False


def test_an_undated_provisional_node_is_flagged_false_rather_than_unflagged(driver):
    """`null IS :: ZONED DATETIME` is TRUE in Neo4j 6.2 -- types are nullable -- so a node
    with no `first_seen` made the whole predicate evaluate to null, and `SET p = null`
    REMOVES the property instead of storing false. A consumer filtering
    `WHERE n.prune_candidate = false` then drops every healthy undated node, which today
    is most of the graph: nothing in src/ writes `first_seen` on these labels.
    """
    with driver.session() as s:
        s.run(
            "MERGE (a:ThreatActor:Provisional {merge_key:'apt-no-clock'}) "
            "SET a.test_fixture = true, a.confidence = 0.05"
        ).consume()

    _drain("prune_flags")

    with driver.session() as s:
        node = s.run(
            "MATCH (a:ThreatActor {merge_key:'apt-no-clock'}) RETURN a AS a"
        ).single()["a"]
    assert node["prune_candidate"] is False
    assert node["prune_reason"] is None


def test_fr_es_10_decayed_inferred_edge_with_no_authoritative_origin_is_flagged(driver):
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-9102'}) SET c.test_fixture = true "
            "MERGE (a:ThreatActor {merge_key:'apt-prune-edge'}) SET a.test_fixture = true "
            "MERGE (c)-[r:EXPLOITED_BY]->(a) "
            "SET r.origin = ['inferred'], r.inferred_confidence = 0.5, "
            "    r.confidence = 0.001, r.last_confirmed = $old",
            old=NOW - timedelta(days=3650),
        ).consume()

    _drain("prune_flags")

    with driver.session() as s:
        flagged = s.run(
            "MATCH ()-[r:EXPLOITED_BY]->(:ThreatActor {merge_key:'apt-prune-edge'}) "
            "RETURN r.prune_candidate AS p"
        ).single()["p"]
    assert flagged is True


def test_fr_es_10_an_edge_a_feed_still_asserts_is_never_flagged(driver):
    """The other half of the edge predicate. A decayed edge that a FEED also asserts is
    never a prune candidate, however long ago its inferred half was corroborated --
    handing L1's retention job an authoritative edge would delete sourced data.
    """
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-9104'}) SET c.test_fixture = true "
            "MERGE (a:ThreatActor {merge_key:'apt-prune-edge-auth'}) "
            "SET a.test_fixture = true "
            "MERGE (c)-[r:EXPLOITED_BY]->(a) "
            "SET r.origin = ['authoritative', 'inferred'], r.inferred_confidence = 0.5, "
            "    r.confidence = 0.001, r.last_confirmed = $old",
            old=NOW - timedelta(days=3650),
        ).consume()

    _drain("prune_flags")

    with driver.session() as s:
        flagged = s.run(
            "MATCH ()-[r:EXPLOITED_BY]->(:ThreatActor {merge_key:'apt-prune-edge-auth'}) "
            "RETURN r.prune_candidate AS p"
        ).single()["p"]
    assert flagged is False


# --- confidence_rescan (FR-ES-08's repair path) ---------------------------------


def _seed_mentioned_provisional(
    driver, key, *, credibility, extraction, cluster, article=None, source=None
):
    """One provisional actor mentioned by one article from one source.

    `article`/`source` are overridable so a node can be given a SECOND, independent piece
    of evidence -- which is what the concurrency tests below need.
    """
    with driver.session() as s:
        s.run(
            "MERGE (src:Source {source_id: $source}) "
            "SET src.test_fixture = true, src.credibility_score = $credibility "
            "MERGE (a:Article {source_guid_key: $article}) "
            "SET a.test_fixture = true, a.story_cluster_id = $cluster "
            "MERGE (n:ThreatActor:Provisional {merge_key: $key}) "
            "SET n.test_fixture = true "
            "MERGE (a)-[:PUBLISHED_BY]->(src) "
            "MERGE (a)-[m:MENTIONS]->(n) SET m.extraction_confidence = $extraction",
            key=key,
            article=article or f"sweep-conf::{key}",
            source=source or f"sweep-conf-source::{credibility}",
            credibility=credibility,
            extraction=extraction,
            cluster=cluster,
        ).consume()


def test_confidence_rescan_rebuilds_a_node_whose_evidence_was_never_applied(driver):
    """FR-ES-08. A dropped or DLQ'd MENTIONS event leaves the edge in the graph but the
    node's confidence at zero. Nothing else in L4 would ever notice -- confidence is the
    one score that accumulates rather than recomputes."""
    _seed_mentioned_provisional(
        driver, "apt-conf-lost", credibility=0.8, extraction=0.5, cluster="story-1"
    )

    _drain("confidence_rescan")

    with driver.session() as s:
        node = s.run(
            "MATCH (n:ThreatActor {merge_key:'apt-conf-lost'}) RETURN n AS n"
        ).single()["n"]
    assert node["confidence"] == pytest.approx(0.4)  # 0.8 * 0.5, one cluster
    assert list(node["contributing_story_cluster_ids"]) == ["story-1"]
    assert list(node["contributing_story_cluster_scores"]) == pytest.approx([0.4])


def test_confidence_rescan_repairs_desynced_parallel_lists(driver):
    """The poison pill: `refine_provisional_confidence` raises forever on a node whose
    two parallel lists differ in length, sending every later MENTIONS event for it to the
    DLQ. Refusing to guess is correct -- ids alone cannot reconstruct scores -- so the
    repair has to come from somewhere that needs neither list."""
    _seed_mentioned_provisional(
        driver, "apt-conf-desync", credibility=0.8, extraction=0.5, cluster="story-1"
    )
    with driver.session() as s:
        s.run(
            "MATCH (n:ThreatActor {merge_key:'apt-conf-desync'}) "
            "SET n.contributing_story_cluster_ids = ['a', 'b', 'c'], "
            "    n.contributing_story_cluster_scores = [0.1]"
        ).consume()

    # Precondition: the node really is poisoned before the sweep touches it.
    with driver.session() as s:
        with pytest.raises(ValueError, match="parallel lists are corrupt"):
            s.execute_write(
                lambda tx: refine_provisional_confidence(
                    tx, label="ThreatActor", key="apt-conf-desync",
                    story_cluster_id="story-2", contribution=0.9,
                )
            )

    _drain("confidence_rescan")

    # ...and afterwards the event path works again, on the rebuilt lists.
    with driver.session() as s:
        new_confidence = s.execute_write(
            lambda tx: refine_provisional_confidence(
                tx, label="ThreatActor", key="apt-conf-desync",
                story_cluster_id="story-2", contribution=0.9,
            )
        )
    # noisy-OR of the rebuilt 0.4 and the new 0.9.
    assert new_confidence == pytest.approx(1 - (1 - 0.4) * (1 - 0.9))


def test_confidence_rescan_is_a_no_op_when_every_event_already_landed(driver):
    """The sweep must not fight the event path. Both compute the same thing -- the
    per-cluster max of credibility x extraction_confidence, noisy-OR'd -- so a node whose
    events all arrived must come out of the rescan byte-identical."""
    _seed_mentioned_provisional(
        driver, "apt-conf-noop", credibility=0.8, extraction=0.5, cluster="story-1"
    )
    with driver.session() as s:
        s.execute_write(
            lambda tx: refine_provisional_confidence(
                tx, label="ThreatActor", key="apt-conf-noop",
                story_cluster_id="story-1", contribution=0.8 * 0.5,
            )
        )
        before = dict(
            s.run(
                "MATCH (n:ThreatActor {merge_key:'apt-conf-noop'}) RETURN n AS n"
            ).single()["n"]
        )

    _drain("confidence_rescan")

    with driver.session() as s:
        after = dict(
            s.run(
                "MATCH (n:ThreatActor {merge_key:'apt-conf-noop'}) RETURN n AS n"
            ).single()["n"]
        )
    assert after == before


def test_confidence_rescan_lowers_a_node_whose_mention_was_retracted(driver):
    """Refinement only ever raises, so a retracted MENTIONS edge (FR-RES-11) would leave
    confidence permanently overstated. The rescan is derived from current graph state and
    must be willing to move it down."""
    _seed_mentioned_provisional(
        driver, "apt-conf-retract", credibility=0.8, extraction=0.5, cluster="story-1"
    )
    _drain("confidence_rescan")
    with driver.session() as s:
        s.run(
            "MATCH (:Article)-[m:MENTIONS]->(:ThreatActor {merge_key:'apt-conf-retract'}) "
            "DELETE m"
        ).consume()

    _drain("confidence_rescan")

    with driver.session() as s:
        node = s.run(
            "MATCH (n:ThreatActor {merge_key:'apt-conf-retract'}) RETURN n AS n"
        ).single()["n"]
    assert node["confidence"] == 0.0
    assert list(node["contributing_story_cluster_ids"]) == []


def test_confidence_rescan_advances_across_pages(driver, monkeypatch):
    """Pagination, not just the happy path. A cursor that fails to advance does NOT hang
    here -- it returns the ORIGINAL cursor, so `done` is true after page one and every
    node past the first page is silently skipped. A sweep that quietly stops at 500 nodes
    looks healthy in CloudWatch, which is exactly why this needs a multi-page test rather
    than a bigger max_pages.
    """
    from src.common.config import get_config

    monkeypatch.setenv("CROSSROADS_SWEEP_BATCH_SIZE", "1")
    get_config.cache_clear()
    keys = ["apt-conf-page-1", "apt-conf-page-2", "apt-conf-page-3"]
    for i, key in enumerate(keys):
        _seed_mentioned_provisional(
            driver, key, credibility=0.8, extraction=0.5, cluster=f"story-page-{i}"
        )

    total, pages, _ = _drain("confidence_rescan")
    get_config.cache_clear()

    assert pages > len(keys)  # one page per node, plus the exhausted page
    assert total >= len(keys)
    with driver.session() as s:
        rebuilt = s.run(
            "MATCH (n:ThreatActor) WHERE n.merge_key IN $keys "
            "RETURN count(n) AS c",
            keys=keys,
        ).single()["c"]
        scored = s.run(
            "MATCH (n:ThreatActor) WHERE n.merge_key IN $keys "
            "AND n.confidence = 0.4 RETURN count(n) AS c",
            keys=keys,
        ).single()["c"]
    assert rebuilt == 3
    assert scored == 3  # every page, not just the first


def test_confidence_rescan_leaves_canonical_nodes_alone(driver):
    """`:Provisional` is in the MATCH itself, so a promoted node keeps its confidence by
    construction rather than by a guard someone could later delete."""
    with driver.session() as s:
        s.run(
            "MERGE (n:ThreatActor {merge_key:'apt-conf-canonical'}) "
            "SET n.test_fixture = true, n.confidence = 1.0"
        ).consume()

    _drain("confidence_rescan")

    with driver.session() as s:
        confidence = s.run(
            "MATCH (n:ThreatActor {merge_key:'apt-conf-canonical'}) "
            "RETURN n.confidence AS c"
        ).single()["c"]
    assert confidence == 1.0


def test_the_rescan_write_sees_evidence_committed_after_its_page_was_chosen(driver):
    """The lock is only worth holding if the DECIDING READ happens inside it.

    Paging and scoring are two statements. If the value written is one the page scan
    computed, a refinement that commits in between is clobbered by a write that holds the
    lock the whole time -- the lock serialises writers but not a writer against a stale
    read. This interleaves the two steps by hand, exactly as a real sweep does when a
    MENTIONS event lands mid-page.
    """
    from src.scoring import confidence as conf

    _seed_mentioned_provisional(
        driver, "apt-conf-race", credibility=0.8, extraction=0.5, cluster="story-race"
    )

    with driver.session() as sweep:
        tx = sweep.begin_transaction()
        # Step 1: the sweep chooses its page.
        eids = [r["eid"] for r in tx.run(conf._CONFIDENCE_SCAN, cursor=None, batch_size=500)]

        # ...and the event path commits new evidence before step 2 runs.
        _seed_mentioned_provisional(
            driver,
            "apt-conf-race",
            credibility=0.9,
            extraction=0.8,
            cluster="story-race-2",
            article="sweep-conf::apt-conf-race-2",
        )
        with driver.session() as events:
            events.execute_write(
                lambda t: refine_from_mention(
                    t,
                    label="ThreatActor",
                    key="apt-conf-race",
                    article_key="sweep-conf::apt-conf-race-2",
                )
            )

        # Step 2: the sweep writes.
        for eid in eids:
            tx.run(conf._CONFIDENCE_WRITE, eid=eid).consume()
        tx.commit()

    with driver.session() as s:
        node = s.run(
            "MATCH (n:ThreatActor {merge_key:'apt-conf-race'}) RETURN n AS n"
        ).single()["n"]
    assert list(node["contributing_story_cluster_ids"]) == ["story-race", "story-race-2"]
    assert node["confidence"] == pytest.approx(noisy_or([0.4, 0.72]))

    # This test hand-drives `conf._CONFIDENCE_SCAN`/`_CONFIDENCE_WRITE` rather than calling
    # `rescan_confidence_batch` -- the only way to interleave the two steps deterministically
    # -- so a future regression that moved the read/lock decision back into Python while
    # leaving these two Cypher constants untouched would go uncaught above. Pin that the
    # production function still IS these two statements.
    import inspect
    source = inspect.getsource(rescan_confidence_batch)
    assert "_CONFIDENCE_SCAN" in source
    assert "_CONFIDENCE_WRITE" in source


def test_concurrent_refinement_and_rescan_lose_no_contribution(driver):
    """Real threads, per CLAUDE.md: a fix that CLAIMS serialisation is not verified until
    concurrent writers run against it.

    N threads each attach a distinct story cluster and refine on it, while rescan threads
    rebuild the same node from the graph. Evidence only ever GROWS here, so the stored
    cluster set must grow monotonically: a rescan that reads under the lock sees every
    committed edge, and a refinement that waits for the lock adds its cluster to whatever
    the rescan just stored. A rescan that decided its value BEFORE the lock writes a set
    that is missing the clusters committed in between -- a lost update, visible as the
    stored set SHRINKING. The final state alone cannot catch that (whichever writer
    happens to go last usually sees everything), so a monitor samples throughout.
    """
    key = "apt-conf-threads"
    n = 10
    errors: list[Exception] = []
    observations: list[frozenset[str]] = []
    stop = threading.Event()
    sweeping_done = threading.Event()
    with driver.session() as s:
        s.run(
            "MERGE (n:ThreatActor:Provisional {merge_key:$key}) SET n.test_fixture = true",
            key=key,
        ).consume()
        # Decoys, so a sweep page is a page and not a single row. A real page is 500
        # nodes, and the gap between choosing the page and writing any one row is what
        # a refinement commits into; a one-node page closes that gap by accident.
        s.run(
            "UNWIND range(1, 40) AS i "
            "MERGE (d:ThreatActor:Provisional {merge_key: 'apt-conf-decoy-' + i}) "
            "SET d.test_fixture = true"
        ).consume()

    def _refine(i):
        try:
            # Staggered, so refinements keep ARRIVING while the sweep runs rather than
            # all landing in one burst that a sweep pass can straddle or miss entirely.
            time.sleep(i * 0.02)
            _seed_mentioned_provisional(
                driver,
                key,
                credibility=0.8,
                extraction=0.5,
                cluster=f"story-thread-{i}",
                article=f"sweep-conf::{key}-{i}",
            )
            with driver.session() as s:
                s.execute_write(
                    lambda tx: refine_from_mention(
                        tx,
                        label="ThreatActor",
                        key=key,
                        article_key=f"sweep-conf::{key}-{i}",
                    )
                )
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    def _rescan():
        # Sweeps for as long as refinements are still arriving. A fixed number of passes
        # is not enough: they all finish in milliseconds against a small graph, so the
        # sweep and the event path would never actually overlap.
        try:
            with driver.session() as s:
                while not sweeping_done.is_set():
                    s.execute_write(
                        lambda tx: rescan_confidence_batch(
                            tx, cursor=None, batch_size=500
                        )
                    )
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    def _monitor():
        try:
            with driver.session() as s:
                while not stop.is_set():
                    row = s.run(
                        "MATCH (n:ThreatActor {merge_key:$key}) "
                        "RETURN coalesce(n.contributing_story_cluster_ids, []) AS ids",
                        key=key,
                    ).single()
                    observations.append(frozenset(row["ids"]))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    refiners = [threading.Thread(target=_refine, args=(i,)) for i in range(n)]
    sweepers = [threading.Thread(target=_rescan) for _ in range(n // 2)]
    monitor = threading.Thread(target=_monitor)
    monitor.start()
    for t in sweepers + refiners:
        t.start()
    for t in refiners:
        t.join(timeout=60)
    sweeping_done.set()
    for t in sweepers:
        t.join(timeout=60)
    stop.set()
    monitor.join(timeout=30)

    assert not errors  # no deadlock, no poisoned parallel lists
    lost = [
        (sorted(before - after), i)
        for i, (before, after) in enumerate(zip(observations, observations[1:]))
        if before - after
    ]
    assert not lost, f"contributions lost from the stored set: {lost}"
    with driver.session() as s:
        node = s.run(
            "MATCH (n:ThreatActor {merge_key:$key}) RETURN n AS n", key=key
        ).single()["n"]
    assert sorted(node["contributing_story_cluster_ids"]) == sorted(
        f"story-thread-{i}" for i in range(n)
    )
    assert node["confidence"] == pytest.approx(noisy_or([0.4] * n))


def test_a_node_promoted_between_the_page_scan_and_the_write_keeps_its_confidence(driver):
    """The write re-asserts `:Provisional` INSIDE the lock, and must.

    The scan's own `:Provisional` filter cannot cover this: it runs before the promotion,
    so the node is legitimately in the page. Only the write can notice. The damage is
    permanent rather than self-healing -- once promoted, no later sweep page ever selects
    the node again, so a clobbered confidence stays clobbered forever.
    """
    from src.scoring import confidence as conf

    _seed_mentioned_provisional(
        driver, "apt-conf-promoted", credibility=0.8, extraction=0.5, cluster="story-prom"
    )

    with driver.session() as sweep:
        tx = sweep.begin_transaction()
        # Step 1: the sweep chooses its page, while the node is still provisional.
        eids = [r["eid"] for r in tx.run(conf._CONFIDENCE_SCAN, cursor=None, batch_size=500)]
        assert eids, "the provisional node must be selected into the page"

        # ...and resolution promotes it to canonical before step 2 runs.
        with driver.session() as promoter:
            promoter.run(
                "MATCH (n:ThreatActor {merge_key:'apt-conf-promoted'}) "
                "REMOVE n:Provisional SET n.confidence = 1.0"
            ).consume()

        # Step 2: the write must decline to touch a node that is no longer provisional.
        for eid in eids:
            tx.run(conf._CONFIDENCE_WRITE, eid=eid).consume()
        tx.commit()

    with driver.session() as s:
        node = s.run(
            "MATCH (n:ThreatActor {merge_key:'apt-conf-promoted'}) RETURN n AS n"
        ).single()["n"]
    assert node["confidence"] == pytest.approx(1.0)


def test_an_out_of_range_credibility_cannot_store_a_confidence_above_one(driver):
    """`confidence` is defined on [0, 1] and the Cypher rebuild must hold that bound.

    Both clamps are load-bearing. `config/sources.yaml` documents `credibility_score` as
    "float in [0, 1]" in a COMMENT, and `source_config._load_config` validates only that
    the field is present, so an operator typo reaches this query unchecked. Two clusters
    are seeded because a single one cannot tell the per-element clamp from the final one.
    """
    _seed_mentioned_provisional(
        driver, "apt-conf-oob", credibility=2.0, extraction=1.0, cluster="story-oob-1"
    )
    _seed_mentioned_provisional(
        driver,
        "apt-conf-oob",
        credibility=2.0,
        extraction=1.0,
        cluster="story-oob-2",
        article="sweep-conf::apt-conf-oob-2",
    )

    _drain("confidence_rescan")

    with driver.session() as s:
        node = s.run(
            "MATCH (n:ThreatActor {merge_key:'apt-conf-oob'}) RETURN n AS n"
        ).single()["n"]
    assert node["confidence"] == pytest.approx(1.0)
    # Each stored contribution is clamped too -- an unclamped 2.0 here would leak the
    # out-of-range value to every consumer that reads the parallel list directly.
    assert list(node["contributing_story_cluster_scores"]) == pytest.approx([1.0, 1.0])
    assert node["confidence"] == pytest.approx(noisy_or([2.0, 2.0]))


# --- pagination: every scan needs a multi-page drain -----------------------------
#
# One page proves nothing. A cursor that fails to advance reports `done` after page one
# and silently skips every later row, which looks perfectly healthy in CloudWatch, so
# each of these seeds more rows than the batch size and asserts every seeded row was
# actually touched -- not merely that more than one page was read.


def test_severity_rescan_advances_across_pages(driver, batch_size_one):
    cves = ["CVE-2026-9201", "CVE-2026-9202", "CVE-2026-9203"]
    with driver.session() as s:
        s.run(
            "UNWIND $cves AS id MERGE (c:CVE {cve_id: id}) "
            "SET c.test_fixture = true, c.cvss_score = 9.1, c.epss_score = 0.5",
            cves=cves,
        ).consume()

    _, pages, _ = _drain("severity_rescan", max_pages=60)

    assert pages > len(cves)
    with driver.session() as s:
        scored = s.run(
            "MATCH (c:CVE) WHERE c.cve_id IN $cves AND c.severity_band IS NOT NULL "
            "RETURN count(c) AS c",
            cves=cves,
        ).single()["c"]
    assert scored == len(cves)


def test_novelty_advances_across_pages(driver, batch_size_one):
    keys = ["apt-novelty-page-1", "apt-novelty-page-2", "apt-novelty-page-3"]
    with driver.session() as s:
        s.run(
            "UNWIND $keys AS k MERGE (a:ThreatActor {merge_key: k}) "
            "SET a.test_fixture = true, a.first_seen = $old, a.relevance_score = 1.0",
            keys=keys,
            old=NOW - timedelta(days=70),
        ).consume()

    _, pages, _ = _drain("novelty", max_pages=60)

    assert pages > len(keys)
    with driver.session() as s:
        rescored = s.run(
            "MATCH (a:ThreatActor) WHERE a.merge_key IN $keys AND a.relevance_score < 1.0 "
            "RETURN count(a) AS c",
            keys=keys,
        ).single()["c"]
    assert rescored == len(keys)


def test_novelty_scan_skips_a_node_missing_its_key_property_without_stalling(driver):
    """A page holding one malformed node (e.g. a legacy `:ThreatActor` created before
    `merge_key` was required) must not stop the scan or stop a normal node on the same
    page from being scored.

    NOTE: deleting `rescan_novelty_batch`'s `if key is None: continue` guard does NOT
    turn this test red -- `score_entity(key=None)` already MATCHes nothing and returns
    None gracefully rather than raising, so the guard is currently fully redundant
    defense-in-depth, not the only thing standing between a malformed node and a stalled
    sweep. This test pins the OUTCOME (scan tolerates the malformed node); it does not
    pin that specific line, because there is currently no code path where removing it
    changes observable behaviour.
    """
    old = NOW - timedelta(days=70)
    with driver.session() as s:
        s.run(
            "CREATE (a:ThreatActor) SET a.test_fixture = true, a.first_seen = $old",
            old=old,
        ).consume()
        s.run(
            "MERGE (a:ThreatActor {merge_key: 'apt-novelty-keyed'}) "
            "SET a.test_fixture = true, a.first_seen = $old",
            old=old,
        ).consume()

    _, pages, last = _drain("novelty", max_pages=60)

    assert last["done"] is True
    with driver.session() as s:
        rescored = s.run(
            "MATCH (a:ThreatActor {merge_key:'apt-novelty-keyed'}) "
            "RETURN a.relevance_score IS NOT NULL AS r"
        ).single()["r"]
    assert rescored is True


def test_decay_advances_across_pages(driver, batch_size_one):
    keys = ["apt-decay-page-1", "apt-decay-page-2", "apt-decay-page-3"]
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-9204'}) SET c.test_fixture = true "
            "WITH c UNWIND $keys AS k "
            "MERGE (a:ThreatActor {merge_key: k}) SET a.test_fixture = true "
            "MERGE (c)-[r:EXPLOITED_BY]->(a) "
            "SET r.origin = ['inferred'], r.inferred_confidence = 0.9, "
            "    r.last_confirmed = $old REMOVE r.confidence",
            keys=keys,
            old=NOW - timedelta(days=3650),
        ).consume()

    _, pages, _ = _drain("decay", max_pages=60)

    assert pages > len(keys)
    with driver.session() as s:
        decayed = s.run(
            "MATCH ()-[r:EXPLOITED_BY]->(a:ThreatActor) WHERE a.merge_key IN $keys "
            "AND r.confidence IS NOT NULL AND r.confidence < 0.9 RETURN count(r) AS c",
            keys=keys,
        ).single()["c"]
    assert decayed == len(keys)


def test_prune_flags_advances_across_pages_for_both_nodes_and_edges(driver, batch_size_one):
    """`prune_flags` is two scans behind one cursor, so it needs both halves drained:
    the node scan hands over to the edge scan only after it exhausts itself.
    """
    keys = ["apt-prune-page-1", "apt-prune-page-2", "apt-prune-page-3"]
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-9205'}) SET c.test_fixture = true "
            "WITH c UNWIND $keys AS k "
            "MERGE (n:ThreatActor:Provisional {merge_key: k}) "
            "SET n.test_fixture = true, n.confidence = 0.05, n.first_seen = $old "
            "MERGE (c)-[r:EXPLOITED_BY]->(n) "
            "SET r.origin = ['inferred'], r.inferred_confidence = 0.5, "
            "    r.confidence = 0.001",
            keys=keys,
            old=NOW - timedelta(days=365),
        ).consume()

    _, pages, _ = _drain("prune_flags", max_pages=60)

    assert pages > 2 * len(keys)  # a page per node, a page per edge, plus the empty ones
    with driver.session() as s:
        flagged_nodes = s.run(
            "MATCH (n:ThreatActor) WHERE n.merge_key IN $keys "
            "AND n.prune_candidate = true RETURN count(n) AS c",
            keys=keys,
        ).single()["c"]
        flagged_edges = s.run(
            "MATCH ()-[r:EXPLOITED_BY]->(n:ThreatActor) WHERE n.merge_key IN $keys "
            "AND r.prune_candidate = true RETURN count(r) AS c",
            keys=keys,
        ).single()["c"]
    assert flagged_nodes == len(keys)
    assert flagged_edges == len(keys)


# --- whole-sweep properties -----------------------------------------------------


def test_confidence_is_repaired_before_pruning_decides_what_to_flag(driver):
    """PHASES order is load-bearing, not cosmetic. This node's STORED confidence is stale
    and below the prune floor, but its actual evidence is well above it -- exactly the
    node a dropped MENTIONS event produces. Sweeping in order repairs it first, so it is
    never flagged; running prune_flags before confidence_rescan condemns a healthy entity
    on a value the same sweep was about to correct.
    """
    _seed_mentioned_provisional(
        driver, "apt-order-test", credibility=0.8, extraction=0.5, cluster="story-order"
    )
    with driver.session() as s:
        s.run(
            "MATCH (n:ThreatActor {merge_key:'apt-order-test'}) "
            "SET n.confidence = 0.05, n.first_seen = $old",
            old=NOW - timedelta(days=365),
        ).consume()

    assert PHASES.index("confidence_rescan") < PHASES.index("prune_flags")
    for phase in PHASES:
        _drain(phase)

    with driver.session() as s:
        node = s.run(
            "MATCH (n:ThreatActor {merge_key:'apt-order-test'}) RETURN n AS n"
        ).single()["n"]
    assert node["confidence"] == pytest.approx(0.4)  # repaired from the MENTIONS edge
    assert node["prune_candidate"] is False  # and therefore never condemned


def test_decay_is_repaired_before_pruning_decides_what_to_flag_for_edges(driver):
    """The edge-side analogue of `test_confidence_is_repaired_before_pruning_decides_what_to_flag`.
    `prune_flags` reads the edge's STORED `confidence`, which only `decay` refreshes --
    `PHASES` puts `decay` before `prune_flags` so a long-uncorroborated edge is judged on
    today's decayed value, not on whatever it happened to be written as by the last event.
    An edge whose stored confidence is stale-high but whose decayed value is below the
    floor must be flagged, and only IF decay ran first in this same sweep.
    """
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-ORDER-EDGE'}) SET c.test_fixture = true "
            "MERGE (a:ThreatActor {merge_key:'apt-order-edge'}) SET a.test_fixture = true "
            "MERGE (c)-[r:EXPLOITED_BY]->(a) "
            # Stale-high stored confidence (as if written before a long quiet period),
            # but inferred_confidence + a very old last_confirmed decay well below the
            # 0.1 floor -- four halflives out, 0.5 * 0.5**4 =~ 0.031.
            "SET r.origin = ['inferred'], r.inferred_confidence = 0.5, "
            "    r.confidence = 0.5, r.last_confirmed = $old",
            old=NOW - timedelta(days=720),
        ).consume()

    assert PHASES.index("decay") < PHASES.index("prune_flags")
    for phase in PHASES:
        _drain(phase)

    with driver.session() as s:
        row = s.run(
            "MATCH ()-[r:EXPLOITED_BY]->(:ThreatActor {merge_key:'apt-order-edge'}) "
            "RETURN r.confidence AS confidence, r.prune_candidate AS prune_candidate"
        ).single()
    assert row["confidence"] < 0.1  # decay ran and repaired the stored value
    assert row["prune_candidate"] is True  # ...and prune_flags saw the repaired value


def test_every_phase_terminates_and_reports_an_exhausted_cursor(driver):
    """The Step Function loops until `done`, so the exit contract is what matters:
    every phase must reach `done` and hand back the empty cursor it type-expects.

    The page COUNT is deliberately not asserted. Cursor pagination cannot report `done`
    until it reads an empty page, and this database is shared across the whole suite, so
    the count is a function of leftover non-fixture nodes rather than of the code.
    """
    for phase in PHASES:
        _, pages, last = _drain(phase)
        assert last["done"] is True
        assert last["cursor"] == ""
        assert last["phase"] == phase
        assert pages >= 1


def test_running_the_whole_sweep_twice_does_not_accumulate(driver):
    """Every phase is a pure recompute, so a second run must not move anything -- that
    is what makes an interrupted sweep safe to retry.

    `relevance_score` is exempt from bitwise equality on purpose: novelty is a function
    of wall-clock time, and the two runs are seconds apart, so it drifts in the far
    decimals BY DESIGN. Idempotency here means "does not accumulate", not "cannot
    change" -- the tolerance below is far tighter than any real accumulation bug
    (double-applied noisy-OR or decay moves these scores in the first or second decimal).
    """
    with driver.session() as s:
        s.run(
            "MERGE (c:CVE {cve_id:'CVE-2026-9103'}) SET c.test_fixture = true, "
            "c.cvss_score = 7.5, c.epss_score = 0.4, c.first_seen = $now", now=NOW,
        ).consume()

    for phase in PHASES:
        _drain(phase)
    with driver.session() as s:
        first = dict(s.run(
            "MATCH (c:CVE {cve_id:'CVE-2026-9103'}) RETURN c AS c"
        ).single()["c"])

    for phase in PHASES:
        _drain(phase)
    with driver.session() as s:
        second = dict(s.run(
            "MATCH (c:CVE {cve_id:'CVE-2026-9103'}) RETURN c AS c"
        ).single()["c"])

    assert set(first) == set(second)
    assert second["relevance_score"] == pytest.approx(first["relevance_score"], rel=1e-3)
    assert {k: v for k, v in second.items() if k != "relevance_score"} == {
        k: v for k, v in first.items() if k != "relevance_score"
    }


def test_unknown_phase_raises(driver):
    with pytest.raises(ValueError, match="unknown sweep phase"):
        handler({"phase": "nonsense", "cursor": None}, None)
