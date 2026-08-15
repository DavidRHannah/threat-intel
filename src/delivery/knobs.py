"""Typed accessor over the delivery knobs (config/delivery.yaml -> env vars -> get_config).

Mirrors src/interop/knobs.py: a frozen dataclass rather than bare get_config calls at each
use site, so every FR-DEL acceptance test runs with no environment at all.
"""

from dataclasses import dataclass

from src.common.config import get_config


def _f(name: str, default: str) -> float:
    return float(get_config(name, default=default))


def _i(name: str, default: str) -> int:
    return int(get_config(name, default=default))


@dataclass(frozen=True)
class DeliveryKnobs:
    dashboard_default_limit: int
    search_result_limit: int
    ttp_heatmap_recency_halflife_days: float

    @classmethod
    def from_config(cls) -> "DeliveryKnobs":
        return cls(
            dashboard_default_limit=_i("dashboard_default_limit", "10"),
            search_result_limit=_i("search_result_limit", "20"),
            ttp_heatmap_recency_halflife_days=_f("ttp_heatmap_recency_halflife_days", "30.0"),
        )
