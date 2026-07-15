import pytest

from src.common import neo4j_driver


@pytest.fixture(autouse=True)
def _reset_singleton():
    neo4j_driver.close_driver()
    yield
    neo4j_driver.close_driver()


class _FakeDriver:
    instances_created = 0

    def __init__(self):
        _FakeDriver.instances_created += 1
        self.closed = False

    def close(self):
        self.closed = True


def test_get_driver_returns_same_instance_on_repeat_calls(monkeypatch):
    _FakeDriver.instances_created = 0
    monkeypatch.setattr(
        neo4j_driver.GraphDatabase, "driver", lambda uri, auth: _FakeDriver()
    )
    first = neo4j_driver.get_driver()
    second = neo4j_driver.get_driver()
    assert first is second
    assert _FakeDriver.instances_created == 1


def test_close_driver_allows_a_fresh_instance_afterward(monkeypatch):
    _FakeDriver.instances_created = 0
    monkeypatch.setattr(
        neo4j_driver.GraphDatabase, "driver", lambda uri, auth: _FakeDriver()
    )
    first = neo4j_driver.get_driver()
    neo4j_driver.close_driver()
    second = neo4j_driver.get_driver()
    assert first is not second
    assert _FakeDriver.instances_created == 2
    assert first.closed is True
