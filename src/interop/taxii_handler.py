"""TAXII 2.1 Discovery / Collections / Objects endpoints (FR-IO-01, FR-IO-02, FR-IO-04).

Each Lambda is a pure API-Gateway-proxy handler: parse the request, query Neo4j
(src/interop/queries.py), map to STIX (src/interop/mapping.py), return an envelope. No
persisted STIX -- generated fresh every call (FR-IO-02). The only write on this path is
`exported = true`, set the first time an object is served (interoperability-layer/
design.md Part 5/6).
"""

import json
from datetime import datetime

from src.common.neo4j_driver import get_driver
from src.interop.knobs import InteropKnobs
from src.interop.mapping import edge_to_stix, node_to_stix, report_to_stix
from src.interop.queries import (
    fetch_edges_page,
    fetch_nodes_page,
    fetch_revoked_nodes_page,
    mark_exported,
    mark_exported_edge,
    scan_revoked_tombstones,
)
from src.interop.stix_ids import NATURAL_KEY_PROP_BY_LABEL, stix_id

_PAGE_SIZE = 100  # per-request page; distinct from the sweep's batch_size knob


def _response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/taxii+json;version=2.1"},
        "body": json.dumps(body),
    }


def discovery_handler(event, context) -> dict:
    knobs = InteropKnobs.from_config()
    return _response(
        200,
        {
            "title": knobs.collection_title,
            "description": "Crossroads threat intelligence, exported as STIX 2.1.",
            "default": "/taxii2/api/",
            "api_roots": ["/taxii2/api/"],
        },
    )


def collections_handler(event, context) -> dict:
    knobs = InteropKnobs.from_config()
    return _response(
        200,
        {
            "collections": [
                {
                    "id": knobs.collection_id,
                    "title": knobs.collection_title,
                    "can_read": True,
                    "can_write": False,
                    "media_types": ["application/stix+json;version=2.1"],
                }
            ]
        },
    )


def _parse_added_after(event: dict) -> datetime | None:
    params = (event or {}).get("queryStringParameters") or {}
    raw = params.get("added_after")
    if not raw:
        return None
    return datetime.fromisoformat(raw)


def objects_handler(event, context) -> dict:
    knobs = InteropKnobs.from_config()
    added_after = _parse_added_after(event)
    driver = get_driver()

    node_objects: list = []

    with driver.session() as session:
        cursor = None
        for _ in range(_PAGE_SIZE):
            rows, cursor = session.execute_read(
                lambda tx, c=cursor: fetch_nodes_page(
                    tx, cursor=c, batch_size=_PAGE_SIZE, floor=knobs.export_confidence_floor,
                    added_after=added_after,
                )
            )
            for row in rows:
                label, props = row["label"], row["props"]
                if label == "Article":
                    continue  # reports need object_refs -- handled in the second pass below
                obj = node_to_stix(label, props, namespace=knobs.stix_namespace)
                node_objects.append(obj)
                key = {NATURAL_KEY_PROP_BY_LABEL[label]: props[NATURAL_KEY_PROP_BY_LABEL[label]]}
                session.execute_write(mark_exported, label, key)
            if cursor is None:
                break

        edge_objects: list = []
        cursor = None
        for _ in range(_PAGE_SIZE):
            rows, cursor = session.execute_read(
                lambda tx, c=cursor: fetch_edges_page(
                    tx, cursor=c, batch_size=_PAGE_SIZE, floor=knobs.export_confidence_floor,
                    added_after=added_after,
                )
            )
            for row in rows:
                obj = edge_to_stix(
                    row["rel_type"], row["start_label"], row["start_props"],
                    row["end_label"], row["end_props"], row["props"],
                    namespace=knobs.stix_namespace,
                )
                edge_objects.append(obj)
                start_key_prop = NATURAL_KEY_PROP_BY_LABEL[row["start_label"]]
                end_key_prop = NATURAL_KEY_PROP_BY_LABEL[row["end_label"]]
                session.execute_write(
                    mark_exported_edge, row["rel_type"], row["start_label"],
                    {start_key_prop: row["start_props"][start_key_prop]},
                    row["end_label"], {end_key_prop: row["end_props"][end_key_prop]},
                )
            if cursor is None:
                break

        report_objects: list = []
        cursor = None
        for _ in range(_PAGE_SIZE):
            rows, cursor = session.execute_read(
                lambda tx, c=cursor: fetch_nodes_page(
                    tx, cursor=c, batch_size=_PAGE_SIZE, floor=0.0,  # Articles aren't score-gated
                    added_after=added_after,
                )
            )
            for row in rows:
                if row["label"] != "Article":
                    continue
                props = row["props"]
                refs = _mentioned_stix_ids(session, props, knobs)
                if not refs:
                    continue  # STIX requires object_refs to be non-empty
                obj = report_to_stix(
                    props, namespace=knobs.stix_namespace, object_refs=refs,
                )
                report_objects.append(obj)
                session.execute_write(
                    mark_exported, "Article", {"source_guid_key": row["props"]["source_guid_key"]},
                )
            if cursor is None:
                break

        revoked_stub_objects: list[dict] = []
        cursor = None
        for _ in range(_PAGE_SIZE):
            rows, cursor = session.execute_read(
                lambda tx, c=cursor: fetch_revoked_nodes_page(
                    tx, cursor=c, batch_size=_PAGE_SIZE, added_after=added_after,
                )
            )
            for row in rows:
                label, props = row["label"], row["props"]
                key_prop = NATURAL_KEY_PROP_BY_LABEL[label]
                sid = stix_id(label, props[key_prop], namespace=knobs.stix_namespace)
                revoked_stub_objects.append(
                    {
                        "type": sid.split("--", 1)[0],
                        "id": sid,
                        "name": props[key_prop],
                        "revoked": True,
                        "modified": props.get("last_updated").isoformat()
                        if props.get("last_updated") else None,
                    }
                )
            if cursor is None:
                break

    for tombstone in scan_revoked_tombstones(added_after=added_after):
        revoked_stub_objects.append(
            {
                "type": tombstone["stix_id"].split("--", 1)[0],
                "id": tombstone["stix_id"],
                "revoked": True,
                "modified": tombstone["revoked_at"],
            }
        )

    objects = [
        json.loads(o.serialize()) for o in (*node_objects, *edge_objects, *report_objects)
    ] + revoked_stub_objects
    return _response(200, {"objects": objects, "more": False})


def _mentioned_stix_ids(session, article_props: dict, knobs: InteropKnobs) -> list[str]:
    """The STIX ids of everything this Article MENTIONS, for the report's object_refs.
    Computed from the article's own MENTIONS edges rather than a stored list -- the
    edge is the source of truth, and this runs once per Article per poll, not per
    request-hot-path.

    Filters on the mentioned node's PERSISTED `exported` flag, not this response's own
    freshly-served ids (I1): a consumer that received CVE-2026-1 on an earlier poll still
    has it, so a Report mentioning it today must keep that ref even though CVE-2026-1
    itself falls outside this poll's `added_after` window and never re-enters
    `node_objects`. Gating in Cypher, not filtering a Python set after the fact, is the
    same convention `fetch_nodes_page` already uses (src/interop/queries.py)."""
    rows = session.execute_read(
        lambda tx: list(
            tx.run(
                "MATCH (:Article {source_guid_key: $key})-[:MENTIONS]->(n) "
                "WHERE coalesce(n.exported, false) = true "
                "RETURN labels(n) AS labels, properties(n) AS props",
                key=article_props["source_guid_key"],
            )
        )
    )
    ids = []
    for row in rows:
        label = next(
            (candidate for candidate in row["labels"] if candidate in NATURAL_KEY_PROP_BY_LABEL),
            None,
        )
        if label is None or label == "Article":
            continue
        key_prop = NATURAL_KEY_PROP_BY_LABEL[label]
        if key_prop not in row["props"]:
            continue
        ids.append(stix_id(label, row["props"][key_prop], namespace=knobs.stix_namespace))
    return ids
