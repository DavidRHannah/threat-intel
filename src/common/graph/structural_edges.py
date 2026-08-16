from src.common.graph.writer import merge_relationship


def resync_categorized_as(tx, *, cve_key: dict, cwe_keys: list[dict]) -> dict:
    created = []
    for cwe_key in cwe_keys:
        outcome = merge_relationship(
            tx, start_label="CVE", start_key=cve_key,
            end_label="CWE", end_key=cwe_key, rel_type="CATEGORIZED_AS",
            on_create={}, on_match={},
        )
        # merge_relationship's outcome comes from the driver's relationships_created
        # counter, so it is correct even though on_create is empty here (Task 2).
        if outcome == "created":
            created.append(cwe_key["cwe_id"])

    wanted = {k["cwe_id"] for k in cwe_keys}
    match_cve = ", ".join(f"{k}: $cve_{k}" for k in cve_key)
    params = {f"cve_{k}": v for k, v in cve_key.items()}
    rows = tx.run(
        f"MATCH (:CVE {{{match_cve}}})-[r:CATEGORIZED_AS]->(w:CWE) RETURN w.cwe_id AS id",
        **params,
    )
    existing = {row["id"] for row in rows}
    to_delete = existing - wanted
    if to_delete:
        tx.run(
            f"MATCH (:CVE {{{match_cve}}})-[r:CATEGORIZED_AS]->(w:CWE) "
            "WHERE w.cwe_id IN $to_delete DELETE r",
            to_delete=list(to_delete), **params,
        )
    return {"created": created, "deleted": list(to_delete)}


def resync_matches(tx, *, cve_key: dict, matches: list[dict]) -> dict:
    created = []
    for match in matches:
        match_key = {"match_criteria_id": match["match_criteria_id"]}
        tx.run(
            "MERGE (m:CPEMatch {match_criteria_id: $id}) SET m += $props",
            id=match["match_criteria_id"],
            props={k: v for k, v in match.items() if k != "match_criteria_id"},
        ).consume()
        outcome = merge_relationship(
            tx, start_label="CVE", start_key=cve_key,
            end_label="CPEMatch", end_key=match_key, rel_type="MATCHES",
            on_create={}, on_match={},
        )
        if outcome == "created":
            created.append(match["match_criteria_id"])

    wanted = {m["match_criteria_id"] for m in matches}
    match_cve = ", ".join(f"{k}: $cve_{k}" for k in cve_key)
    params = {f"cve_{k}": v for k, v in cve_key.items()}
    rows = tx.run(
        f"MATCH (:CVE {{{match_cve}}})-[r:MATCHES]->(m:CPEMatch) RETURN m.match_criteria_id AS id",
        **params,
    )
    existing = {row["id"] for row in rows}
    to_delete = existing - wanted
    if to_delete:
        tx.run(
            f"MATCH (:CVE {{{match_cve}}})-[r:MATCHES]->(m:CPEMatch) "
            "WHERE m.match_criteria_id IN $to_delete DELETE r",
            to_delete=list(to_delete), **params,
        )
    return {"created": created, "deleted": list(to_delete)}
