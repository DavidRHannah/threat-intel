import pytest

from src.common.graph.assertion_edges import validate_edge_direction


def test_associated_with_must_end_at_ioc():
    validate_edge_direction("ASSOCIATED_WITH", end_label="IOC")  # no raise
    with pytest.raises(ValueError):
        validate_edge_direction("ASSOCIATED_WITH", end_label="CVE")


def test_indicates_is_the_only_way_to_link_ioc_to_cve():
    validate_edge_direction("INDICATES", end_label="CVE")  # no raise
