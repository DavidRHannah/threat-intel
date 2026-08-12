from src.interop.knobs import InteropKnobs


def test_defaults():
    k = InteropKnobs.from_config()
    assert k.export_confidence_floor == 0.3
    assert k.stix_namespace == "5a2c1f2e-6b8a-4b0a-9c3e-2f6a7d8e9b10"
    assert k.collection_id == "883d0e40-1e0e-4e2b-9a7c-8e2f6c5a1d90"
    assert k.collection_title == "Crossroads Threat Intelligence"


def test_env_var_override(monkeypatch):
    from src.common.config import get_config

    monkeypatch.setenv("CROSSROADS_EXPORT_CONFIDENCE_FLOOR", "0.5")
    get_config.cache_clear()
    assert InteropKnobs.from_config().export_confidence_floor == 0.5
