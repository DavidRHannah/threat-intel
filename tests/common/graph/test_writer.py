import threading

import pytest

from src.common.graph.writer import EndpointNotFoundError, merge_relationship
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
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


@pytest.fixture
def two_nodes(driver):
    with driver.session() as s:
        s.run(
            "MERGE (a:CVE {cve_id: 'CVE-2026-0001'}) SET a.test_fixture = true "
            "MERGE (b:ThreatActor {merge_key: 'apt-writer-test'}) SET b.test_fixture = true"
        ).consume()
    return driver


def test_merge_creates_exactly_one_edge_when_asserted_twice(two_nodes):
    outcomes = []
    for _ in range(2):
        with two_nodes.session() as s:
            outcomes.append(
                s.execute_write(
                    lambda tx: merge_relationship(
                        tx,
                        start_label="CVE", start_key={"cve_id": "CVE-2026-0001"},
                        end_label="ThreatActor", end_key={"merge_key": "apt-writer-test"},
                        rel_type="EXPLOITED_BY",
                        on_create={"confidence": 0.5},
                        on_match={"confidence": 0.5},
                    )
                )
            )
    assert outcomes == ["created", "matched"]  # FR-RG-01: the outcome contract
    with two_nodes.session() as s:
        count = s.run(
            "MATCH (:CVE {cve_id:'CVE-2026-0001'})-[r:EXPLOITED_BY]->"
            "(:ThreatActor {merge_key:'apt-writer-test'}) RETURN count(r) AS c"
        ).single()["c"]
    assert count == 1  # FR-RG-01


def test_second_write_with_different_confidence_updates_not_duplicates(two_nodes):
    with two_nodes.session() as s:
        s.execute_write(
            lambda tx: merge_relationship(
                tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0001"},
                end_label="ThreatActor", end_key={"merge_key": "apt-writer-test"},
                rel_type="EXPLOITED_BY", on_create={"confidence": 0.5}, on_match={"confidence": 0.5},
            )
        )
        s.execute_write(
            lambda tx: merge_relationship(
                tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0001"},
                end_label="ThreatActor", end_key={"merge_key": "apt-writer-test"},
                rel_type="EXPLOITED_BY", on_create={"confidence": 0.9}, on_match={"confidence": 0.9},
            )
        )
        rows = list(s.run(
            "MATCH (:CVE {cve_id:'CVE-2026-0001'})-[r:EXPLOITED_BY]->"
            "(:ThreatActor {merge_key:'apt-writer-test'}) RETURN r.confidence AS conf"
        ))
    assert len(rows) == 1 and rows[0]["conf"] == 0.9  # FR-RG-02


def test_concurrent_writers_produce_no_duplicate_and_no_deadlock(two_nodes):
    errors = []

    def _write():
        try:
            with two_nodes.session() as s:
                s.execute_write(
                    lambda tx: merge_relationship(
                        tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0001"},
                        end_label="ThreatActor", end_key={"merge_key": "apt-writer-test"},
                        rel_type="EXPLOITED_BY",
                        on_create={"confidence": 0.7}, on_match={"confidence": 0.7},
                    )
                )
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=_write) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not errors  # FR-RG-03: no deadlock
    with two_nodes.session() as s:
        count = s.run(
            "MATCH (:CVE {cve_id:'CVE-2026-0001'})-[r:EXPLOITED_BY]->"
            "(:ThreatActor {merge_key:'apt-writer-test'}) RETURN count(r) AS c"
        ).single()["c"]
    assert count == 1  # FR-RG-03: no duplicate parallel edge


def test_outcome_is_correct_when_on_create_carries_no_properties(two_nodes):
    # Task 6's exact call shape (on_create={}, on_match={}). The original first_observed
    # sentinel returned "matched" here even on a genuine create, silently emptying Task 6's
    # created list. The driver's counters do not depend on caller-supplied properties.
    def _write(tx):
        return merge_relationship(
            tx, start_label="CVE", start_key={"cve_id": "CVE-2026-0001"},
            end_label="ThreatActor", end_key={"merge_key": "apt-writer-test"},
            rel_type="CATEGORIZED_AS", on_create={}, on_match={},
        )

    with two_nodes.session() as s:
        assert s.execute_write(_write) == "created"
        assert s.execute_write(_write) == "matched"


def test_missing_endpoint_raises_rather_than_reporting_success(two_nodes):
    with two_nodes.session() as s:
        with pytest.raises(EndpointNotFoundError):
            s.execute_write(
                lambda tx: merge_relationship(
                    tx, start_label="CVE", start_key={"cve_id": "CVE-DOES-NOT-EXIST"},
                    end_label="ThreatActor", end_key={"merge_key": "apt-writer-test"},
                    rel_type="EXPLOITED_BY", on_create={}, on_match={},
                )
            )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"rel_type": "EXPLOITED_BY) DELETE b //"},
        {"end_label": "ThreatActor) DELETE b //"},
    ],
)
def test_interpolated_identifiers_are_validated(two_nodes, kwargs):
    call = {
        "start_label": "CVE", "start_key": {"cve_id": "CVE-2026-0001"},
        "end_label": "ThreatActor", "end_key": {"merge_key": "apt-writer-test"},
        "rel_type": "EXPLOITED_BY", "on_create": {}, "on_match": {},
        **kwargs,
    }
    with two_nodes.session() as s:
        with pytest.raises(ValueError):
            s.execute_write(lambda tx: merge_relationship(tx, **call))
