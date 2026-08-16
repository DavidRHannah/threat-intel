"""TTP heatmap query + Lambda handler (FR-DEL-03).

Aggregates each TTP's inbound USES edges, weighted by recency (exponential decay off
`last_confirmed`), active-exploiter count, and the exploiters' relevance_score -- per
delivery-layer/design.md Part 3: "not exploiter severity" (severity is CVE-only), weight by
relevance_score, which IS computed for ThreatActor/MalwareFamily/Campaign (src/scoring/
relevance.py's SCORED_LABELS). Heat is normalized to [0, 1] by dividing by the batch max, same
convention as frontend/src/api/mockData.js's mockTtpHeatmap.
"""

import json

from src.common.neo4j_driver import get_driver
from src.delivery.knobs import DeliveryKnobs
from src.delivery.queries import entity_subgraph_type

_TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance"},
    {"id": "TA0042", "name": "Resource Development"},
    {"id": "TA0001", "name": "Initial Access"},
    {"id": "TA0002", "name": "Execution"},
    {"id": "TA0003", "name": "Persistence"},
    {"id": "TA0004", "name": "Privilege Escalation"},
    {"id": "TA0005", "name": "Defense Evasion"},
    {"id": "TA0006", "name": "Credential Access"},
    {"id": "TA0007", "name": "Discovery"},
    {"id": "TA0008", "name": "Lateral Movement"},
    {"id": "TA0009", "name": "Collection"},
    {"id": "TA0011", "name": "Command and Control"},
    {"id": "TA0010", "name": "Exfiltration"},
    {"id": "TA0040", "name": "Impact"},
]

# STIX kill-chain phase-name slugs (as written by src/collection/stix/attck_sync.py's
# `tactic` list property) mapped to MITRE ATT&CK TA00xx tactic ids. `TTP.tactic` is a LIST
# of these slugs, not a scalar TA-code -- a technique can legitimately belong to more than one
# tactic, so fetch_ttp_heatmap emits one heatmap entry per (technique, mapped tactic) pair.
_TACTIC_ID_BY_PHASE_NAME = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}

_FETCH = """
MATCH (t:TTP)
WHERE NOT coalesce(t.is_revoked, false)
OPTIONAL MATCH (exploiter)-[u:USES]->(t)
WHERE exploiter IS NULL OR NOT coalesce(exploiter.is_revoked, false)
WITH t, collect(CASE WHEN exploiter IS NULL THEN null ELSE
    {id: elementId(exploiter), labels: labels(exploiter), name: exploiter.name,
     relevance: coalesce(exploiter.relevance_score, 0.0),
     last_confirmed: u.last_confirmed} END) AS raw_exploiters
RETURN t.technique_id AS id, t.name AS name, t.tactic AS tactics,
       [x IN raw_exploiters WHERE x IS NOT NULL] AS exploiters
"""


def fetch_ttp_heatmap(tx, *, halflife_days: float) -> list[dict]:
    rows = list(tx.run(_FETCH))
    now_utc = tx.run("RETURN datetime() AS now").single()["now"].to_native()

    techniques = []
    for row in rows:
        exploiters = row["exploiters"]
        weight_sum = 0.0
        for ex in exploiters:
            last_confirmed = ex["last_confirmed"]
            if last_confirmed is None:
                recency_weight = 0.0
            else:
                age_days = max((now_utc - last_confirmed.to_native()).days, 0)
                recency_weight = 0.5 ** (age_days / halflife_days)
            weight_sum += ex["relevance"] * recency_weight
        top_exploiters = [
            {"id": ex["id"], "type": entity_subgraph_type(ex["labels"]), "name": ex["name"]}
            for ex in sorted(exploiters, key=lambda e: e["relevance"], reverse=True)[:3]
        ]
        tactic_ids = [
            _TACTIC_ID_BY_PHASE_NAME[phase]
            for phase in (row["tactics"] or [])
            if phase in _TACTIC_ID_BY_PHASE_NAME
        ]
        for tactic_id in tactic_ids:
            techniques.append({
                "id": row["id"], "name": row["name"], "tactic": tactic_id,
                "heat_raw": weight_sum, "exploiter_count": len(exploiters),
                "top_exploiters": top_exploiters,
            })

    max_heat = max((t["heat_raw"] for t in techniques), default=0.0)
    for t in techniques:
        t["heat"] = round(t["heat_raw"] / max_heat, 4) if max_heat > 0 else 0.0
        del t["heat_raw"]
    return techniques


def _response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


def handler(event, context) -> dict:
    knobs = DeliveryKnobs.from_config()
    driver = get_driver()
    with driver.session() as session:
        techniques = session.execute_read(
            lambda tx: fetch_ttp_heatmap(tx, halflife_days=knobs.ttp_heatmap_recency_halflife_days)
        )
    return _response(200, {"tactics": _TACTICS, "techniques": techniques})
