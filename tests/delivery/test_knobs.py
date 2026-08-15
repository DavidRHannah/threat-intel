from src.delivery.knobs import DeliveryKnobs


def test_from_config_reads_delivery_yaml_defaults():
    knobs = DeliveryKnobs.from_config()
    assert knobs.dashboard_default_limit == 10
    assert knobs.search_result_limit == 20
    assert knobs.ttp_heatmap_recency_halflife_days == 30.0
