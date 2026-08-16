from src.common.natural_keys import article_key, ioc_key, asset_key


def test_article_key_combines_source_id_and_guid():
    assert article_key("krebs", "guid-123") == "krebs::guid-123"


def test_ioc_key_combines_value_and_type():
    assert ioc_key("1.2.3.4", "ip") == "1.2.3.4::ip"


def test_asset_key_lowercases_vendor_and_product_only():
    assert asset_key("Cisco", "IOS XE", "17.3.1") == "cisco::ios xe::17.3.1"


def test_asset_key_is_stable_for_same_inputs():
    assert asset_key("acme", "x", "1.0") == asset_key("acme", "x", "1.0")
