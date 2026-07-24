"""Deterministic resolution of CVE, TTP, and IOC mentions (Phase 2, Step 2.1 of
`plans/02-nlp.md`, FR-RES-01, FR-RES-03, FR-RES-04, FR-RES-07).

Each `resolve_*` function MERGEs (or, for TTP, only MATCHes -- FR-RES-03 forbids
creating new TTP nodes) the target node on its natural key, then writes a
`MENTIONS` evidence edge via `src.common.graph.evidence_edges.write_mentions_edge`
for every resolved mention. A `rejected` mention gets no node and no edge
(FR-RES-07). Both the node write and the edge write happen inside the same
`execute_write` transaction, per this codebase's idempotent-per-stage convention.

The NVD-404 tombstone path (FR-RES-02) is L1's responsibility -- this module
only creates the CVE stub and flags `enrichment_pending=true` for L1's trigger
to pick up.
"""

from __future__ import annotations

from datetime import datetime, timezone

from neo4j import Driver

from src.common.graph.evidence_edges import write_mentions_edge
from src.common.natural_keys import ioc_key
from src.nlp.extraction.deterministic import _classify_ioc
from src.nlp.messages import RawMention, ResolvedEntity
from src.nlp.resolution._shared import article_ref_from_id


def _now() -> datetime:
    return datetime.now(timezone.utc)


def resolve_cve(driver: Driver, mention: RawMention) -> ResolvedEntity:
    """FR-RES-01: match an existing `cve_id` or lazy-create the stub with
    `enrichment_pending=true` for L1's NVD trigger. Always resolves (a
    format-valid CVE mention is never rejected at this stage)."""
    cve_id = mention.surface_text.upper()
    article_ref = article_ref_from_id(mention.article_id)

    def _tx(tx):
        tx.run(
            "MERGE (c:CVE {cve_id: $cve_id}) "
            "ON CREATE SET c.enrichment_pending = true",
            cve_id=cve_id,
        ).consume()
        write_mentions_edge(
            tx,
            article_ref=article_ref,
            entity_label="CVE",
            entity_key={"cve_id": cve_id},
            extraction_confidence=mention.extraction_confidence,
            extracted_at=_now(),
            context_snippet=mention.context_snippet,
        )

    with driver.session() as session:
        session.execute_write(_tx)

    return ResolvedEntity(
        canonical_node_key=cve_id,
        entity_type="cve",
        resolution_status="resolved",
        node_confidence=mention.extraction_confidence,
    )


def resolve_ttp(driver: Driver, mention: RawMention) -> ResolvedEntity:
    """FR-RES-03: match `technique_id` against an existing MITRE TTP node;
    never create one. Unknown id -> `rejected`, no node, no edge (FR-RES-07)."""
    technique_id = mention.surface_text.upper()
    article_ref = article_ref_from_id(mention.article_id)

    def _tx(tx):
        record = tx.run(
            "MATCH (t:TTP {technique_id: $technique_id}) RETURN t.technique_id AS id",
            technique_id=technique_id,
        ).single()
        if record is None:
            return False
        write_mentions_edge(
            tx,
            article_ref=article_ref,
            entity_label="TTP",
            entity_key={"technique_id": technique_id},
            extraction_confidence=mention.extraction_confidence,
            extracted_at=_now(),
            context_snippet=mention.context_snippet,
        )
        return True

    with driver.session() as session:
        matched = session.execute_write(_tx)

    if not matched:
        return ResolvedEntity(
            canonical_node_key="",
            entity_type="ttp",
            resolution_status="rejected",
            node_confidence=0.0,
        )

    return ResolvedEntity(
        canonical_node_key=technique_id,
        entity_type="ttp",
        resolution_status="resolved",
        node_confidence=mention.extraction_confidence,
    )


def resolve_ioc(driver: Driver, mention: RawMention) -> ResolvedEntity:
    """FR-RES-04: match or create an IOC node keyed on the synthetic
    `value_type_key = ioc_key(value, ioc_type)` -- never a raw `(value,
    ioc_type)` MERGE key (that pair has no uniqueness enforcement; `UNIQUE`
    constraints ignore nulls on an unconstrained composite pair). Node
    `confidence` inherits the mention's `extraction_confidence` on create.

    `ioc_type` is not carried on `RawMention` -- it is re-derived here from
    `surface_text` via the same classifier Extraction used
    (`src.nlp.extraction.deterministic._classify_ioc`), reused rather than
    duplicated. An unclassifiable value (should not occur for a mention that
    Extraction itself produced) is treated symmetrically with the TTP
    unknown-id case: rejected, no node, no edge.
    """
    article_ref = article_ref_from_id(mention.article_id)
    raw_value = mention.surface_text
    ioc_type = _classify_ioc(raw_value)

    if ioc_type is None:
        return ResolvedEntity(
            canonical_node_key="",
            entity_type="ioc",
            resolution_status="rejected",
            node_confidence=0.0,
        )

    value = raw_value.lower() if ioc_type != "url" else raw_value
    value_type_key = ioc_key(value, ioc_type)

    def _tx(tx):
        tx.run(
            "MERGE (i:IOC {value_type_key: $key}) "
            "ON CREATE SET i.value = $value, i.ioc_type = $ioc_type, "
            "i.confidence = $confidence",
            key=value_type_key,
            value=value,
            ioc_type=ioc_type,
            confidence=mention.extraction_confidence,
        ).consume()
        write_mentions_edge(
            tx,
            article_ref=article_ref,
            entity_label="IOC",
            entity_key={"value_type_key": value_type_key},
            extraction_confidence=mention.extraction_confidence,
            extracted_at=_now(),
            context_snippet=mention.context_snippet,
        )

    with driver.session() as session:
        session.execute_write(_tx)

    return ResolvedEntity(
        canonical_node_key=value_type_key,
        entity_type="ioc",
        resolution_status="resolved",
        node_confidence=mention.extraction_confidence,
    )
