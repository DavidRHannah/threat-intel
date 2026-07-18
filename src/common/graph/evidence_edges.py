from datetime import datetime

# Import the module, not the functions: `natural_keys.article_key` must not be shadowed by a
# local/parameter of the same name.
from src.common import natural_keys
from src.common.graph.writer import merge_relationship


def _article_start_key(article_ref: dict) -> dict:
    return {"source_guid_key": natural_keys.article_key(**article_ref)}


def write_mentions_edge(
    tx, *, article_ref: dict, entity_label: str, entity_key: dict,
    extraction_confidence: float, extracted_at: datetime,
    context_snippet: str | None = None,
) -> str:
    props = {
        "extraction_confidence": extraction_confidence,
        "extracted_at": extracted_at,
        "context_snippet": context_snippet,
    }
    return merge_relationship(
        tx, start_label="Article", start_key=_article_start_key(article_ref),
        end_label=entity_label, end_key=entity_key, rel_type="MENTIONS",
        on_create=props, on_match=props,
    )


def write_published_by_edge(tx, *, article_ref: dict, source_key: dict) -> str:
    return merge_relationship(
        tx, start_label="Article", start_key=_article_start_key(article_ref),
        end_label="Source", end_key=source_key, rel_type="PUBLISHED_BY",
        on_create={}, on_match={},
    )
