import json
from datetime import datetime, timedelta, timezone

import pytest

from src.common.neo4j_driver import close_driver, get_driver
from src.delivery.ttp_heatmap_handler import fetch_ttp_heatmap, handler


@pytest.fixture
def driver():
    d = get_driver()
    d.verify_connectivity()
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    yield d
    with d.session() as s:
        s.run("MATCH (n) WHERE n.test_fixture = true DETACH DELETE n").consume()
    close_driver()


def test_technique_with_recent_high_relevance_exploiters_beats_dormant_one(driver):
    """FR-DEL-03: recently-active high-relevance exploiters burn hotter than a dormant TTP."""
    now = datetime.now(timezone.utc)
    recent = now - timedelta(days=1)
    old = now - timedelta(days=400)
    with driver.session() as session:
        session.run(
            "CREATE (hot:TTP {technique_id: 'T-HOT', name: 'Hot', "
            "  tactic: ['initial-access'], test_fixture: true})"
            "CREATE (cold:TTP {technique_id: 'T-COLD', name: 'Cold', "
            "  tactic: ['execution'], test_fixture: true})"
            "CREATE (actor:ThreatActor {merge_key: 'hot-actor', name: 'Hot Actor', "
            "  relevance_score: 0.9, test_fixture: true})"
            "CREATE (dormant:ThreatActor {merge_key: 'cold-actor', name: 'Cold Actor', "
            "  relevance_score: 0.9, test_fixture: true})"
            "WITH hot, cold, actor, dormant "
            "CREATE (actor)-[:USES {last_confirmed: datetime($recent), "
            "  test_fixture: true}]->(hot) "
            "CREATE (dormant)-[:USES {last_confirmed: datetime($old), "
            "  test_fixture: true}]->(cold)",
            recent=recent.isoformat(), old=old.isoformat(),
        )
    with driver.session() as session:
        techniques = session.execute_read(lambda tx: fetch_ttp_heatmap(tx, halflife_days=30.0))
    by_id = {t["id"]: t for t in techniques}
    assert by_id["T-HOT"]["heat"] > by_id["T-COLD"]["heat"]
    assert by_id["T-HOT"]["exploiter_count"] == 1


def test_top_exploiters_carry_real_id_and_type_per_entity_label(driver):
    """A drawer link needs a real elementId + the entity's actual label-derived type --
    not just a name -- and different exploiter labels (ThreatActor vs Campaign) must
    resolve to their own distinct type, not one hardcoded value."""
    with driver.session() as session:
        session.run(
            "CREATE (t:TTP {technique_id: 'T-MIXED', name: 'Mixed', "
            "  tactic: ['initial-access'], test_fixture: true})"
            "CREATE (actor:ThreatActor {merge_key: 'mixed-actor', name: 'Mixed Actor', "
            "  relevance_score: 0.9, test_fixture: true})"
            "CREATE (camp:Campaign {merge_key: 'mixed-campaign', name: 'Mixed Campaign', "
            "  relevance_score: 0.9, test_fixture: true})"
            "WITH t, actor, camp "
            "CREATE (actor)-[:USES {test_fixture: true}]->(t) "
            "CREATE (camp)-[:USES {test_fixture: true}]->(t)"
        )
    with driver.session() as session:
        techniques = session.execute_read(lambda tx: fetch_ttp_heatmap(tx, halflife_days=30.0))
    row = next(t for t in techniques if t["id"] == "T-MIXED")
    by_name = {ex["name"]: ex for ex in row["top_exploiters"]}
    assert by_name["Mixed Actor"]["type"] == "threat_actor"
    assert by_name["Mixed Campaign"]["type"] == "campaign"
    assert by_name["Mixed Actor"]["id"] and by_name["Mixed Campaign"]["id"]
    assert by_name["Mixed Actor"]["id"] != by_name["Mixed Campaign"]["id"]


def test_technique_with_no_exploiters_has_zero_heat(driver):
    with driver.session() as session:
        session.run(
            "CREATE (:TTP {technique_id: 'T-NONE', name: 'None', "
            "  tactic: ['initial-access'], test_fixture: true})"
        )
    with driver.session() as session:
        techniques = session.execute_read(lambda tx: fetch_ttp_heatmap(tx, halflife_days=30.0))
    none_row = next(t for t in techniques if t["id"] == "T-NONE")
    assert none_row["heat"] == 0.0
    assert none_row["exploiter_count"] == 0


def test_technique_with_multiple_tactics_produces_one_entry_per_tactic(driver):
    """FR-DEL-03: TTP.tactic is a list (attck_sync.py) -- multi-tactic techniques fan out."""
    with driver.session() as session:
        session.run(
            "CREATE (:TTP {technique_id: 'T-MULTI', name: 'Multi', "
            "  tactic: ['initial-access', 'execution'], test_fixture: true})"
        )
    with driver.session() as session:
        techniques = session.execute_read(lambda tx: fetch_ttp_heatmap(tx, halflife_days=30.0))
    multi_rows = [t for t in techniques if t["id"] == "T-MULTI"]
    assert {t["tactic"] for t in multi_rows} == {"TA0001", "TA0002"}
    assert len(multi_rows) == 2


def test_handler_returns_tactics_and_techniques(driver):
    response = handler({}, None)
    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert len(body["tactics"]) == 14
    assert isinstance(body["techniques"], list)
