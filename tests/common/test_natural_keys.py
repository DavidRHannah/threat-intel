from src.common.natural_keys import article_key, ioc_key


def test_article_key_combines_source_id_and_guid():
    assert article_key("krebs", "guid-123") == "krebs::guid-123"


def test_ioc_key_combines_value_and_type():
    assert ioc_key("1.2.3.4", "ip") == "1.2.3.4::ip"
