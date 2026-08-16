"""Matches one Asset against candidate CPEMatch records and writes AFFECTS edges
(design spec §5). Version comparison is pure Python (src.assets.matching); Cypher here
only fetches candidates and writes the resulting edge -- same split as L4's
formulas.py + thin Cypher (design spec Decision 7)."""

from datetime import datetime, timezone
from typing import Any

from src.assets.matching import version_satisfies
from src.common.graph.writer import merge_relationship


def candidate_matches_for(tx, *, vendor: str, product: str) -> list[dict[str, Any]]:
    rows = tx.run(
        "MATCH (c:CVE)-[:MATCHES]->(m:CPEMatch) "
        "WHERE toLower(m.vendor) = toLower($vendor) AND toLower(m.product) = toLower($product) "
        "RETURN c.cve_id AS cve_id, m.match_criteria_id AS match_criteria_id, "
        "  m.version AS version, m.version_start_including AS version_start_including, "
        "  m.version_start_excluding AS version_start_excluding, "
        "  m.version_end_including AS version_end_including, "
        "  m.version_end_excluding AS version_end_excluding, m.vulnerable AS vulnerable",
        vendor=vendor, product=product,
    )
    return [dict(r) for r in rows]


def write_affects_edge(
    tx, *, cve_id: str, asset_key: str, match_criteria_id: str, now: datetime
) -> None:
    """The one place an AFFECTS edge is written. match_asset, the event handler
    (Task 7), and the sweep (Task 8) all call this instead of each hand-rolling their
    own merge_relationship call -- do not reintroduce a second copy of this Cypher."""
    merge_relationship(
        tx,
        start_label="CVE", start_key={"cve_id": cve_id},
        end_label="Asset", end_key={"asset_key": asset_key},
        rel_type="AFFECTS",
        on_create={"matched_at": now.isoformat(), "matched_via": match_criteria_id},
        on_match={"matched_at": now.isoformat(), "matched_via": match_criteria_id},
    )


def match_asset(tx, *, asset: dict, now: datetime | None = None) -> list[str]:
    at = now or datetime.now(timezone.utc)
    candidates = candidate_matches_for(tx, vendor=asset["vendor"], product=asset["product"])
    hit_ids: list[str] = []
    for candidate in candidates:
        if not version_satisfies(asset["version"], candidate):
            continue
        write_affects_edge(
            tx, cve_id=candidate["cve_id"], asset_key=asset["asset_key"],
            match_criteria_id=candidate["match_criteria_id"], now=at,
        )
        hit_ids.append(candidate["match_criteria_id"])
    return hit_ids
