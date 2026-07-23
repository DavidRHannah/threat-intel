"""Shared message-shape dataclasses passed between L2 NLP pipeline stages.

These mirror the umbrella design's Interfaces 1-3 (see
`entity-extraction-nlp-layer/design.md`): `RawMention` (Extraction -> Resolution),
`ResolvedArticle`/`ResolvedEntity` (Resolution -> Dedup/Inference), and
`StoryCluster` (Dedup -> Inference). Every stage imports these instead of
re-declaring ad hoc dicts, and every dataclass round-trips through JSON via
`to_dict()`/`from_dict()` for SQS message bodies.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RawMention:
    article_id: str
    entity_type: str
    surface_text: str
    char_span: tuple[int, int]
    extraction_confidence: float
    context_snippet: str

    def to_dict(self) -> dict:
        return {
            "article_id": self.article_id,
            "entity_type": self.entity_type,
            "surface_text": self.surface_text,
            "char_span": list(self.char_span),
            "extraction_confidence": self.extraction_confidence,
            "context_snippet": self.context_snippet,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RawMention":
        return cls(
            article_id=data["article_id"],
            entity_type=data["entity_type"],
            surface_text=data["surface_text"],
            char_span=tuple(data["char_span"]),
            extraction_confidence=data["extraction_confidence"],
            context_snippet=data["context_snippet"],
        )


@dataclass
class ResolvedEntity:
    canonical_node_key: str
    entity_type: str
    resolution_status: str
    node_confidence: float

    def to_dict(self) -> dict:
        return {
            "canonical_node_key": self.canonical_node_key,
            "entity_type": self.entity_type,
            "resolution_status": self.resolution_status,
            "node_confidence": self.node_confidence,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ResolvedEntity":
        return cls(
            canonical_node_key=data["canonical_node_key"],
            entity_type=data["entity_type"],
            resolution_status=data["resolution_status"],
            node_confidence=data["node_confidence"],
        )


@dataclass
class ResolvedArticle:
    article_id: str
    title: str
    published_at: str
    source_id: str
    resolved_entities: list[ResolvedEntity] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "article_id": self.article_id,
            "title": self.title,
            "published_at": self.published_at,
            "source_id": self.source_id,
            "resolved_entities": [e.to_dict() for e in self.resolved_entities],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ResolvedArticle":
        return cls(
            article_id=data["article_id"],
            title=data["title"],
            published_at=data["published_at"],
            source_id=data["source_id"],
            resolved_entities=[
                ResolvedEntity.from_dict(e) for e in data.get("resolved_entities", [])
            ],
        )


@dataclass
class StoryCluster:
    story_cluster_id: str
    article_ids: list[str] = field(default_factory=list)
    union_resolved_entities: list[ResolvedEntity] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "story_cluster_id": self.story_cluster_id,
            "article_ids": list(self.article_ids),
            "union_resolved_entities": [e.to_dict() for e in self.union_resolved_entities],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "StoryCluster":
        return cls(
            story_cluster_id=data["story_cluster_id"],
            article_ids=list(data.get("article_ids", [])),
            union_resolved_entities=[
                ResolvedEntity.from_dict(e) for e in data.get("union_resolved_entities", [])
            ],
        )
