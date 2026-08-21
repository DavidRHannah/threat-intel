import json

import boto3
import pytest
from moto import mock_aws

from src.common import config, neo4j_driver


@pytest.fixture(autouse=True)
def _reset_singleton():
    neo4j_driver.close_driver()
    config.get_config.cache_clear()
    yield
    neo4j_driver.close_driver()
    config.get_config.cache_clear()


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


@mock_aws
def test_get_driver_reads_one_consolidated_ssm_param_in_non_local_env(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("CROSSROADS_ENV", "dev")
    ssm = boto3.client("ssm", region_name="us-east-1")
    ssm.put_parameter(
        Name="/crossroads/dev/neo4j_credentials",
        Value=json.dumps(
            {"uri": "bolt://aura:7687", "user": "neo4j", "password": "s3cr3t"}
        ),
        Type="SecureString",
    )
    captured = {}

    def _fake_driver(uri, auth):
        captured["uri"] = uri
        captured["auth"] = auth
        return _FakeDriver()

    monkeypatch.setattr(neo4j_driver.GraphDatabase, "driver", _fake_driver)
    neo4j_driver.get_driver()
    assert captured == {"uri": "bolt://aura:7687", "auth": ("neo4j", "s3cr3t")}
