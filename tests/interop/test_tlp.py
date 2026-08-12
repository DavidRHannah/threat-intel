from src.interop.tlp import TLP_CLEAR


def test_tlp_clear_has_the_fixed_oasis_id():
    assert TLP_CLEAR.id == "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"


def test_tlp_clear_serializes_to_valid_stix_json():
    payload = TLP_CLEAR.serialize()
    assert '"tlp_2_0": "clear"' in payload or '"tlp_2_0":"clear"' in payload.replace(" ", "")
