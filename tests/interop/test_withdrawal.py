from datetime import datetime, timezone

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.interop.withdrawal import revoke_batch


@pytest.fixture
def driver():
    """Local fixture, same convention as every other Neo4j-backed test file in this
    repo -- there is no shared conftest.py. Every node/edge this file creates must be
    tagged `test_fixture: true` so this cleanup finds it."""
    d = get_driver()
    d.verify_connectivity()
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


def test_exported_node_below_floor_gets_revoked(driver):
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-2026-1', confidence: 0.1, exported: true, "
            "test_fixture: true})"
        )
        count, cursor = session.execute_write(
            lambda tx: revoke_batch(
                tx, cursor=None, batch_size=10, floor=0.3,
                now=datetime(2026, 8, 11, tzinfo=timezone.utc),
            )
        )
        record = session.run(
            "MATCH (c:CVE {cve_id: 'CVE-2026-1'}) "
            "RETURN c.revoked AS revoked, c.exported AS exported, c.last_updated AS lu"
        ).single()
    assert count == 1
    assert record["revoked"] is True
    assert record["exported"] is False
    assert record["lu"] == datetime(2026, 8, 11, tzinfo=timezone.utc)


def test_exported_node_still_above_floor_untouched(driver):
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-2026-1', confidence: 0.9, exported: true, "
            "test_fixture: true})"
        )
        count, _ = session.execute_write(
            lambda tx: revoke_batch(
                tx, cursor=None, batch_size=10, floor=0.3, now=datetime.now(timezone.utc),
            )
        )
        record = session.run(
            "MATCH (c:CVE {cve_id: 'CVE-2026-1'}) RETURN c.revoked AS revoked"
        ).single()
    assert count == 0
    assert record["revoked"] is None


def test_never_exported_node_untouched(driver):
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-2026-1', confidence: 0.1, test_fixture: true})"
        )  # exported unset
        count, _ = session.execute_write(
            lambda tx: revoke_batch(
                tx, cursor=None, batch_size=10, floor=0.3, now=datetime.now(timezone.utc),
            )
        )
    assert count == 0


def test_exported_source_node_gets_revoked(driver):
    """I7: withdrawal.py redeclared its own exportable-label list and omitted `Source`
    (queries.py's EXPORTABLE_NODE_LABELS is the correct, single list -- see
    src/interop/stix_ids.py). A `Source` node that fell below the export floor after
    being served would never be picked up by the withdrawal sweep, leaving a consumer
    holding a gated-out object forever with no tombstone."""
    with driver.session() as session:
        session.run(
            "CREATE (:Source {url: 'https://example.com/feed', confidence: 0.1, "
            "exported: true, test_fixture: true})"
        )
        count, _ = session.execute_write(
            lambda tx: revoke_batch(
                tx, cursor=None, batch_size=10, floor=0.3,
                now=datetime(2026, 8, 11, tzinfo=timezone.utc),
            )
        )
        record = session.run(
            "MATCH (s:Source {url: 'https://example.com/feed'}) RETURN s.revoked AS revoked"
        ).single()
    assert count == 1
    assert record["revoked"] is True


def test_already_revoked_not_rescanned(driver):
    """exported=false is a stable end state -- a second sweep run must not re-flag it."""
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'CVE-2026-1', confidence: 0.1, exported: false, "
            "revoked: true, test_fixture: true})"
        )
        count, _ = session.execute_write(
            lambda tx: revoke_batch(
                tx, cursor=None, batch_size=10, floor=0.3, now=datetime.now(timezone.utc),
            )
        )
    assert count == 0


def test_pruned_object_also_revoked_even_above_floor(driver):
    with driver.session() as session:
        session.run(
            "CREATE (:ThreatActor {merge_key: 'x', confidence: 0.9, exported: true, "
            "prune_candidate: true, test_fixture: true})"
        )
        count, _ = session.execute_write(
            lambda tx: revoke_batch(
                tx, cursor=None, batch_size=10, floor=0.3, now=datetime.now(timezone.utc),
            )
        )
    assert count == 1


def test_mixed_page_does_not_silently_skip_a_later_below_floor_node(driver):
    """Regression test for a bug found in review: computing the cursor with a fresh
    `exported = true` re-query AFTER the revoke write silently drops any node the
    revoke step just flipped to `exported = false`, so on a page mixing a revoked
    node with an untouched one the cursor can jump straight past a later,
    not-yet-evaluated below-floor node -- permanently skipping it.

    Seeds 4 exported CVEs in creation (elementId) order: A, B below floor (should
    revoke), C above floor (should NOT revoke), D below floor (should revoke, but
    only reachable on a LATER page once batch_size=2 splits {A,B} from {C,D}).
    Drives revoke_batch in a loop to exhaustion (cursor becomes None) and asserts
    D actually got revoked -- not just A and B from the first page.
    """
    with driver.session() as session:
        session.run(
            "CREATE (:CVE {cve_id: 'A', confidence: 0.1, exported: true, test_fixture: true}) "
            "CREATE (:CVE {cve_id: 'B', confidence: 0.1, exported: true, test_fixture: true}) "
            "CREATE (:CVE {cve_id: 'C', confidence: 0.9, exported: true, test_fixture: true}) "
            "CREATE (:CVE {cve_id: 'D', confidence: 0.1, exported: true, test_fixture: true})"
        )

        cursor = None
        total = 0
        pages = 0
        while True:
            count, cursor = session.execute_write(
                lambda tx, cursor=cursor: revoke_batch(
                    tx, cursor=cursor, batch_size=2, floor=0.3, now=datetime.now(timezone.utc),
                )
            )
            total += count
            pages += 1
            assert pages <= 10, "sweep did not terminate -- cursor never became None"
            if cursor is None:
                break

        records = {
            r["id"]: r["revoked"]
            for r in session.run(
                "MATCH (c:CVE) WHERE c.test_fixture = true "
                "RETURN c.cve_id AS id, c.revoked AS revoked"
            )
        }

    assert total == 3
    assert records["A"] is True
    assert records["B"] is True
    assert records["D"] is True
    assert records["C"] is None
