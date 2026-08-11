from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.scoring.significance import stamp_significant_event

NOW = datetime(2026, 7, 30, tzinfo=timezone.utc)


@pytest.fixture
def driver():
    d = get_driver()
    d.verify_connectivity()
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
        s.run(
            "MERGE (a:ThreatActor {merge_key:'apt-sig-test'}) SET a.test_fixture = true"
        ).consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


def _stamp(driver, at, label="ThreatActor", key="apt-sig-test"):
    with driver.session() as s:
        s.execute_write(
            lambda tx: stamp_significant_event(tx, label=label, key=key, at=at)
        )


def _read(driver):
    with driver.session() as s:
        return s.run(
            "MATCH (a:ThreatActor {merge_key:'apt-sig-test'}) "
            "RETURN a.last_significant_event AS t"
        ).single()["t"]


def test_stamps_the_timestamp(driver):
    _stamp(driver, NOW)
    assert _read(driver).to_native().replace(tzinfo=timezone.utc) == NOW


def test_is_monotonic_so_out_of_order_redelivery_cannot_rewind_the_clock(driver):
    """SNS is at-least-once and unordered. A redelivered older event must not un-spike
    an entity's novelty."""
    _stamp(driver, NOW)
    _stamp(driver, NOW - timedelta(days=30))
    assert _read(driver).to_native().replace(tzinfo=timezone.utc) == NOW


def test_a_newer_event_does_advance_the_clock(driver):
    """The monotonic CASE must not be so conservative that it never updates."""
    _stamp(driver, NOW - timedelta(days=30))
    _stamp(driver, NOW)
    assert _read(driver).to_native().replace(tzinfo=timezone.utc) == NOW


def test_is_idempotent(driver):
    _stamp(driver, NOW)
    _stamp(driver, NOW)
    assert _read(driver).to_native().replace(tzinfo=timezone.utc) == NOW


def test_unknown_entity_is_a_no_op_not_an_error(driver):
    _stamp(driver, NOW, key="nope")


def test_an_unscored_label_is_a_no_op_not_an_error(driver):
    """resolve_key_prop returns None for labels with no scoring key; the function must
    return BEFORE interpolating anything into Cypher.

    Asserting only "it didn't raise" is NOT enough, and this test used to do exactly that.
    Deleting the guard entirely left it green, because `_STAMP.format(key_prop=None)`
    produces `MATCH (n:TTP {None: $key})` -- and `None` is a legal Cypher property name,
    so the query parses, matches nothing, and no-ops. The only thing that actually pins
    the guard is proving no query was issued at all.
    """
    spy = MagicMock()
    stamp_significant_event(spy, label="TTP", key="T1059", at=NOW)
    spy.run.assert_not_called()


@pytest.mark.parametrize(
    "seed",
    [
        "'2020-01-01 00:00:00'",          # abuse.ch's raw string shape
        "date('2020-01-01')",             # a Neo4j DATE
        "localdatetime('2020-01-01T00:00:00')",  # naive: no zone
        "12345",                          # not temporal at all
    ],
)
def test_a_non_zoned_stored_value_is_overwritten_not_honoured(driver, seed):
    """Neo4j returns NULL -- not false -- for an ordering comparison between incomparable
    temporal types. Without the type check the `< $at` arm is NULL, the CASE falls to
    ELSE, and the clock stays pinned at the junk value FOREVER: no error, no log, and
    unlike a future timestamp it never self-heals. The graph really does contain these
    (src/collection/rest/abusech.py writes raw strings into first_seen).
    """
    with driver.session() as s:
        s.run(
            f"MATCH (a:ThreatActor {{merge_key:'apt-sig-test'}}) "
            f"SET a.last_significant_event = {seed}"
        ).consume()

    _stamp(driver, NOW)

    assert _read(driver).to_native().replace(tzinfo=timezone.utc) == NOW


def test_a_naive_at_is_rejected(driver):
    """A naive datetime stores as a LOCALDATETIME, which is incomparable with every later
    zoned stamp -- one naive write would pin this entity's clock permanently. The type is
    annotated `datetime`, which does not distinguish the two, so it is checked."""
    with pytest.raises(ValueError, match="timezone-aware"):
        _stamp(driver, datetime(2026, 7, 30))


def test_an_injection_shaped_label_is_rejected(driver):
    """Both the label and the key property are interpolated into the Cypher, so the
    label must be validated rather than trusted."""
    with pytest.raises(ValueError):
        _stamp(driver, NOW, label="ThreatActor) DETACH DELETE (n")
