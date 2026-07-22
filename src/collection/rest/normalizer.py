"""REST normalizer protocol and data structures for Collection layer (L1).

Defines the SourceNormalizer Protocol that all Category B sources (NVD, CISA KEV, GHSA,
OTX, abuse.ch) must implement, along with the NodeUpsert dataclass that represents
a single entity to be written to the graph.

FR-DC-18.
"""

from dataclasses import dataclass
from typing import Any, Protocol


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
