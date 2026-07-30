"""DynamoDB access for the RE-target-content-hash-keyed relation-extraction
cache (`RECache`).

The table is injected as a `boto3` DynamoDB table resource -- this module
opens no client/resource of its own. The table name/region/credentials are
resolved by the caller (a Lambda resolves the table from an env var CDK sets
via `get_config("re_cache_table_name")`; tests inject a moto fixture table).
See `technical-specification.md` §4: `RECache`, partition key
`re_target_content_hash` -> cached relation-extraction result.

FR-INF-07: when Dedup re-emits a `StoryCluster` after a non-representative
member joins but the representative article's text (and therefore its
content hash) is unchanged, the caller (Step 4.4's Lambda handler) looks the
hash up here first and skips `extract_relations` (Step 4.1) on a hit. This
module does not call the LLM and does not decide whether to skip it -- it is
pure cache storage/retrieval.
"""

from decimal import Decimal
from typing import Any

from src.nlp.inference.relation_extraction import CandidateRelation


def get_cached_result(table: Any, content_hash: str) -> list[CandidateRelation] | None:
    """Return the cached relations for `content_hash`, or None on a cache miss."""
    response = table.get_item(Key={"re_target_content_hash": content_hash})
    item = response.get("Item")
    if item is None:
        return None
    return [
        CandidateRelation.from_dict(_floats_from_decimal(r)) for r in item["relations"]
    ]


def put_cached_result(
    table: Any, content_hash: str, relations: list[CandidateRelation]
) -> None:
    """Store `relations` (Step 4.1's `extract_relations` output) under `content_hash`."""
    table.put_item(
        Item={
            "re_target_content_hash": content_hash,
            "relations": [_floats_to_decimal(r.to_dict()) for r in relations],
        }
    )


def _floats_to_decimal(value: Any) -> Any:
    """Recursively convert `float`s to `Decimal` -- DynamoDB's number type has
    no native float representation."""
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _floats_to_decimal(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_floats_to_decimal(v) for v in value]
    return value


def _floats_from_decimal(value: Any) -> Any:
    """Recursively convert `Decimal`s back to `float` on the way out."""
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, dict):
        return {k: _floats_from_decimal(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_floats_from_decimal(v) for v in value]
    return value
