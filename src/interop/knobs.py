"""Typed accessor over the interop knobs (config/interop.yaml -> env vars -> get_config).

A frozen dataclass rather than bare get_config calls at each use site, same rationale as
src/scoring/knobs.py: it lets every FR-IO acceptance test run with no environment at all.
"""

from dataclasses import dataclass

from src.common.config import get_config


def _f(name: str, default: str) -> float:
    return float(get_config(name, default=default))


def _i(name: str, default: str) -> int:
    return int(get_config(name, default=default))


@dataclass(frozen=True)
class InteropKnobs:
    export_confidence_floor: float
    stix_namespace: str
    collection_id: str
    collection_title: str
    sweep_batch_size: int

    @classmethod
    def from_config(cls) -> "InteropKnobs":
        return cls(
            export_confidence_floor=_f("export_confidence_floor", "0.3"),
            stix_namespace=get_config(
                "stix_namespace", default="5a2c1f2e-6b8a-4b0a-9c3e-2f6a7d8e9b10"
            ),
            collection_id=get_config(
                "collection_id", default="883d0e40-1e0e-4e2b-9a7c-8e2f6c5a1d90"
            ),
            collection_title=get_config(
                "collection_title", default="Crossroads Threat Intelligence"
            ),
            sweep_batch_size=_i("sweep_batch_size", "500"),
        )
