import re

from neo4j import ManagedTransaction

# Labels and relationship types cannot be parameterized in Cypher, so they must be
# interpolated. Everything interpolated is validated first: this is the single library
# every L1/L2/L3 graph write flows through.
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class EndpointNotFoundError(LookupError):
    """Raised when a MERGE's start or end node does not exist, so no edge was written."""


def _check_identifier(value: str, what: str) -> str:
    if not _IDENTIFIER.match(value):
        raise ValueError(f"invalid {what}: {value!r}")
    return value


def _match_clause(var: str, label: str, key: dict) -> str:
    _check_identifier(label, "label")
    props = ", ".join(
        f"{_check_identifier(k, 'key property')}: ${var}_{k}" for k in key
    )
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
    _check_identifier(rel_type, "rel_type")

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
    RETURN elementId(r) AS rid
    """
    # Endpoint existence and update-count are different questions: a matched edge whose
    # on_match is empty (Task 6) writes nothing, so counters.contains_updates would be False
    # for a perfectly good edge. The RETURN row proves the endpoints matched; the counter
    # distinguishes create from match.
    result = tx.run(query, **params)
    record = result.single()
    summary = result.consume()
    if record is None:
        raise EndpointNotFoundError(
            f"no {start_label} {start_key} -> {end_label} {end_key} endpoints to link"
        )
    return "created" if summary.counters.relationships_created else "matched"
