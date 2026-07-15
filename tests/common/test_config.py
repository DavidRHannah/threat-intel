import os
import boto3
import pytest
from moto import mock_aws

from src.common import config


@pytest.fixture(autouse=True)
def _clear_cache_and_env(monkeypatch):
    config.get_config.cache_clear()
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("CROSSROADS_ENV", raising=False)
    monkeypatch.delenv("CROSSROADS_NEO4J_URI", raising=False)
    yield
    config.get_config.cache_clear()


def test_local_env_reads_from_environment_variable(monkeypatch):
    monkeypatch.setenv("CROSSROADS_NEO4J_URI", "bolt://localhost:7687")
    assert config.get_config("neo4j_uri") == "bolt://localhost:7687"


def test_local_env_falls_back_to_default(monkeypatch):
    assert config.get_config("neo4j_uri", default="bolt://default:7687") == "bolt://default:7687"


def test_local_env_raises_without_default_or_env_var():
    with pytest.raises(KeyError):
        config.get_config("missing_param")


@mock_aws
def test_non_local_env_reads_from_ssm(monkeypatch):
    monkeypatch.setenv("CROSSROADS_ENV", "dev")
    ssm = boto3.client("ssm", region_name="us-east-1")
    ssm.put_parameter(
        Name="/crossroads/dev/neo4j_uri",
        Value="bolt://aura:7687",
        Type="SecureString",
    )
    assert config.get_config("neo4j_uri") == "bolt://aura:7687"


@mock_aws
def test_non_local_env_falls_back_to_default_when_param_missing(monkeypatch):
    monkeypatch.setenv("CROSSROADS_ENV", "dev")
    assert config.get_config("missing_param", default="fallback") == "fallback"


def test_explicit_env_var_overrides_ssm_lookup(monkeypatch):
    monkeypatch.setenv("CROSSROADS_ENV", "dev")
    monkeypatch.setenv("CROSSROADS_NEO4J_URI", "bolt://override:7687")
    assert config.get_config("neo4j_uri") == "bolt://override:7687"
