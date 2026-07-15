from neo4j import ManagedTransaction


def _match_clause(var: str, label: str, key: dict) -> str:
    props = ", ".join(f"{k}: ${var}_{k}" for k in key)
    return f"({var}:{label} {{{props}}})"


def merge_relationship(
    tx: ManagedTransaction,
    *,
    start_label: str,
    start_key: dict,
    end_label: str,
    end_key: dict,
    rel_type: str,
    on_create: dict,
    on_match: dict,
) -> str:
    params = {f"a_{k}": v for k, v in start_key.items()}
    params.update({f"b_{k}": v for k, v in end_key.items()})
    params["on_create"] = on_create
    params["on_match"] = on_match

    query = f"""
    MATCH {_match_clause("a", start_label, start_key)},
          {_match_clause("b", end_label, end_key)}
    WITH a, b,
         CASE WHEN elementId(a) <= elementId(b) THEN [a, b] ELSE [b, a] END AS ordered
    CALL apoc.lock.nodes(ordered)
    WITH a, b
    MERGE (a)-[r:{rel_type}]->(b)
    ON CREATE SET r += $on_create
    ON MATCH  SET r += $on_match
    RETURN CASE WHEN r.first_observed = $on_create_first_observed
                THEN 'created' ELSE 'matched' END AS outcome
    """
    # Distinguish create/match without a second round-trip: compare a sentinel the caller
    # is expected to put in on_create (first_observed) against what's on the relationship
    # post-merge. Callers that don't set first_observed get 'matched' by convention — fine,
    # since only assertion/evidence edges (which always set first_observed) need this signal.
    params["on_create_first_observed"] = on_create.get("first_observed")
    result = tx.run(query, **params).single()
    return result["outcome"] if result else "matched"
