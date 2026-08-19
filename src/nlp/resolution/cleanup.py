"""One-off cleanup of low-confidence LLM-derived provisional entities (FR-EX-13).

Before FR-EX-13's confidence floor landed in `extraction/llm_extractor.py`, every
LLM candidate reached the graph regardless of confidence. This finds and removes
the `ThreatActor`/`MalwareFamily` `:Provisional` nodes that guard would now have
dropped, so the graph reflects the same standard going forward as it does now.

A node whose best `MENTIONS` confidence still clears the floor is kept even if it
also has a weaker mention (per-node judgment, not per-mention). A node with any
non-`MENTIONS` relationship is left alone and reported as skipped rather than
deleted blind -- a `:Provisional` node is not expected to have picked up another
edge type, so one is a signal to look, not to proceed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from neo4j import Driver

_ID_SHAPE_REGEX = r"(?i)^(cve-\d{4}-\d+|ghsa-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$"

_FIND_CANDIDATES = """
    MATCH (n:Provisional)
    WHERE n:ThreatActor OR n:MalwareFamily
    OPTIONAL MATCH (n)<-[m:MENTIONS]-()
    WITH n, max(m.extraction_confidence) AS best_confidence
    WHERE best_confidence IS NULL OR best_confidence < $floor OR n.merge_key =~ $id_shape
    OPTIONAL MATCH (n)-[r]-()
    WITH n, best_confidence, collect(DISTINCT type(r)) AS rel_types
    RETURN n.merge_key AS merge_key, labels(n) AS labels,
           best_confidence AS best_confidence, rel_types AS rel_types
"""


def find_removal_candidates(driver: Driver, floor: float) -> list[dict]:
    """Provisional ThreatActor/MalwareFamily nodes whose best mention confidence
    is below `floor`, or whose merge_key is CVE/GHSA-ID-shaped regardless of
    confidence. Each result also carries its non-MENTIONS relationship types so
    the caller can decide whether it's safe to delete."""
    with driver.session() as s:
        result = s.run(_FIND_CANDIDATES, floor=floor, id_shape=_ID_SHAPE_REGEX)
        return [dict(record) for record in result]


@dataclass
class CleanupResult:
    deleted: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def delete_low_confidence_entities(driver: Driver, floor: float) -> CleanupResult:
    """Delete every removal candidate that has no relationship besides
    MENTIONS; skip (and report) any that does."""
    result = CleanupResult()
    for candidate in find_removal_candidates(driver, floor):
        other_edges = set(candidate["rel_types"]) - {"MENTIONS"}
        if other_edges:
            result.skipped.append(candidate["merge_key"])
            continue
        label = "ThreatActor" if "ThreatActor" in candidate["labels"] else "MalwareFamily"
        with driver.session() as s:
            s.run(
                f"MATCH (n:{label} {{merge_key: $key}}) DETACH DELETE n",
                key=candidate["merge_key"],
            ).consume()
        result.deleted.append(candidate["merge_key"])
    return result
