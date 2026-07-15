import threading

import pytest
from neo4j import GraphDatabase

from src.common.graph.writer import merge_relationship

NEO4J_URI = "bolt://localhost:7687"
NEO4J_AUTH = ("neo4j", "crossroads-dev")


@pytest.fixture
def driver():
    d = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
    d.verify_connectivity()
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    d.close()


@pytest.fixture
def two_nodes(driver):
    with driver.session() as s:
        s.run(
            "MERGE (a:CVE {cve_id: 'CVE-2026-0001'}) SET a.test_fixture = true "
            "MERGE (b:ThreatActor {merge_key: 'apt-writer-test'}) SET b.test_fixture = true"
        ).consume()
    return driver


def test_merge_creates_exactly_one_edge_when_asserted_twice(two_nodes):
    for _ in range(2):
        with two_nodes.session() as s:
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
