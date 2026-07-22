"""REST normalizer protocol and data structures for Collection layer (L1).

Defines the SourceNormalizer Protocol that all Category B sources (NVD, CISA KEV, GHSA,
OTX, abuse.ch) must implement, along with the NodeUpsert dataclass that represents
a single entity to be written to the graph.

FR-DC-18.
"""

from dataclasses import dataclass
from typing import Any, Protocol

DEFAULT_SOURCE_CREDIBILITY_SCORE = 0.5


def read_source_credibility_score(
    tx, source_id: str, *, default: float = DEFAULT_SOURCE_CREDIBILITY_SCORE
) -> float:
    """Read `Source.credibility_score` for `source_id`, to feed a real
    `upsert_authoritative_assertion` call instead of a hardcoded placeholder.

    `Source` nodes are populated by `src.collection.source_config.sync_sources` from
    `config/sources.yaml` on every deploy, so this should always find a real value in
    practice. If the `Source` node or its `credibility_score` property is missing anyway
    (e.g. a source referenced before its first deploy-time sync), fall back to `default`
    rather than raising: this is enrichment metadata for scoring, not a hard dependency,
    and a missing `Source` must not block the IOC/edge write it's attached to.

    Must be called from inside the same `session.execute_write(tx, ...)` transaction
    that writes the assertion edge -- never a separate round trip -- so the read can't
    observe a stale or uncommitted `Source` state relative to the write it feeds.
    """
    row = tx.run(
        "MATCH (s:Source {source_id: $source_id}) RETURN s.credibility_score AS score",
        source_id=source_id,
    ).single()
    if row is None or row["score"] is None:
        return default
    return row["score"]


@dataclass
class NodeUpsert:
    """Represents a single node to be upserted into the graph.

    Attributes:
        label: The Neo4j node label (e.g., "Article", "IOC", "CVE").
        natural_key: Dictionary of properties that form the node's natural key.
            Used by the graph writer to MERGE on this key.
        properties: Dictionary of additional properties to set on the node.
    """

    label: str
    natural_key: dict[str, Any]
    properties: dict[str, Any]


class SourceNormalizer(Protocol):
    """Protocol that all REST-based source normalizers must implement.

    A SourceNormalizer takes a raw response from a REST API and transforms it
    into a list of NodeUpsert objects ready for ingestion into the graph.
    """

    def normalize(self, raw_response: Any) -> list[NodeUpsert]:
        """Normalize a raw API response into a list of NodeUpsert objects.

        Args:
            raw_response: The raw response from the source's REST API
                (typically parsed JSON dict or list).

        Returns:
            A list of NodeUpsert objects representing entities extracted from
            the response.
        """
        ...
