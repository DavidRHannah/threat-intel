"""Tests for REST normalizer protocol and SSM credential loader.

Tests verify FR-DC-18: credentials never come from source code or plaintext config,
and the SourceNormalizer protocol can be implemented for Category B sources.
"""

import boto3
import pytest
from moto import mock_aws

from src.collection.rest.normalizer import NodeUpsert
from src.collection.rest.ssm_credentials import load_credential
from src.common import config


@pytest.fixture(autouse=True)
def _clear_cache_and_env(monkeypatch):
    """Clear config cache and clean up environment between tests."""
    config.get_config.cache_clear()
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("CROSSROADS_ENV", raising=False)
    monkeypatch.delenv("CROSSROADS_OTX_API_KEY", raising=False)
    yield
    config.get_config.cache_clear()


# Tests for load_credential


def test_load_credential_reads_from_environment_variable(monkeypatch):
    """load_credential should read from CROSSROADS_{source_id}_{env_name} env var."""
    monkeypatch.setenv("CROSSROADS_OTX_API_KEY", "test-api-key-123")
    assert load_credential("otx", "api_key") == "test-api-key-123"


@mock_aws
def test_load_credential_reads_from_ssm_in_non_local_env(monkeypatch):
    """load_credential should read from SSM in non-local environments."""
    monkeypatch.setenv("CROSSROADS_ENV", "dev")
    ssm = boto3.client("ssm", region_name="us-east-1")
    ssm.put_parameter(
        Name="/crossroads/dev/otx_api_key",
        Value="ssm-api-key-456",
        Type="SecureString",
    )
    assert load_credential("otx", "api_key") == "ssm-api-key-456"


def test_load_credential_raises_keyerror_when_missing_locally(monkeypatch):
    """load_credential should raise KeyError if credential is not found (local env)."""
    with pytest.raises(KeyError):
        load_credential("missing_source", "api_key")


@mock_aws
def test_load_credential_raises_keyerror_when_missing_in_ssm(monkeypatch):
    """load_credential should raise KeyError if credential is not found in SSM."""
    monkeypatch.setenv("CROSSROADS_ENV", "dev")
    with pytest.raises(KeyError):
        load_credential("missing_source", "api_key")


def test_load_credential_never_has_default(monkeypatch):
    """load_credential should never silently return a default for security credentials."""
    # This verifies the function signature never accepts a default parameter
    # by checking that passing one raises TypeError
    with pytest.raises(TypeError):
        load_credential("otx", "api_key", default="should-not-work")  # type: ignore


def test_load_credential_with_different_env_names(monkeypatch):
    """load_credential should support different credential names for same source."""
    monkeypatch.setenv("CROSSROADS_GITHUB_TOKEN", "token-value")
    monkeypatch.setenv("CROSSROADS_GITHUB_USERNAME", "user-value")
    assert load_credential("github", "token") == "token-value"
    assert load_credential("github", "username") == "user-value"


# Tests for NodeUpsert dataclass


def test_node_upsert_has_required_fields():
    """NodeUpsert should have label, natural_key, and properties fields."""
    upsert = NodeUpsert(
        label="Article",
        natural_key={"source_id": "krebs", "guid": "abc123"},
        properties={"title": "Test", "url": "https://example.com"},
    )
    assert upsert.label == "Article"
    assert upsert.natural_key == {"source_id": "krebs", "guid": "abc123"}
    assert upsert.properties == {"title": "Test", "url": "https://example.com"}


def test_node_upsert_natural_key_can_be_empty():
    """NodeUpsert natural_key can be an empty dict for nodes without composite keys."""
    upsert = NodeUpsert(
        label="Label",
        natural_key={},
        properties={"name": "value"},
    )
    assert upsert.natural_key == {}
    assert upsert.properties == {"name": "value"}


def test_node_upsert_properties_can_be_empty():
    """NodeUpsert properties can be empty if only natural_key matters."""
    upsert = NodeUpsert(
        label="Label",
        natural_key={"id": "123"},
        properties={},
    )
    assert upsert.natural_key == {"id": "123"}
    assert upsert.properties == {}


# Tests for SourceNormalizer protocol


class FakeNormalizer:
    """A minimal implementation of SourceNormalizer for testing."""

    # Type hint to show this class implements SourceNormalizer Protocol
    def normalize(self, raw_response: object) -> list[NodeUpsert]:
        """Return a list of NodeUpsert from a fake response."""
        return [
            NodeUpsert(
                label="Article",
                natural_key={"source_id": "test", "guid": "1"},
                properties={"title": "Article 1"},
            ),
            NodeUpsert(
                label="IOC",
                natural_key={"value": "1.2.3.4", "type": "ip"},
                properties={"source": "test"},
            ),
        ]


def test_source_normalizer_protocol_with_fake_normalizer():
    """A fake normalizer implementing SourceNormalizer protocol should work."""
    normalizer = FakeNormalizer()
    result = normalizer.normalize({"raw": "data"})

    assert len(result) == 2
    assert result[0].label == "Article"
    assert result[0].natural_key == {"source_id": "test", "guid": "1"}
    assert result[1].label == "IOC"
    assert result[1].natural_key == {"value": "1.2.3.4", "type": "ip"}


def test_source_normalizer_protocol_returns_list_of_node_upsert():
    """SourceNormalizer.normalize() should return list[NodeUpsert]."""
    normalizer = FakeNormalizer()
    result = normalizer.normalize({})

    assert isinstance(result, list)
    assert all(isinstance(item, NodeUpsert) for item in result)
