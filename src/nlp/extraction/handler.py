"""Extraction Lambda handler (Phase 1, Step 1.3 of plans/02-nlp.md).

Subscribes DIRECTLY to the `graph-writes` SNS topic (not an SQS queue) --
per the reconciliation with `plans/01-data-collection.md`, L1's Extraction
Lambda publishes a node-shaped `{node_label: "Article", ...}` announcement to
that topic after every Article MERGE, and this Lambda picks it up from there.
This is why FR-EX-12 (no Neo4j access from this stage) is satisfiable at
all: the article text arrives in the notification itself, never via a graph
read-back.

FR-EX-12: this module must NEVER import or call anything from `neo4j` or
`src.common.neo4j_driver` / `src.common.graph`. Enforced by
`tests/nlp/extraction/test_handler.py::test_handler_module_never_imports_neo4j`,
which runs this module in a clean subprocess and asserts neo4j never enters
`sys.modules`.
"""

from __future__ import annotations

import json
from typing import Any

import boto3

from src.common.config import get_config
from src.nlp.extraction.deterministic import dedup_within_type, extract_deterministic
from src.nlp.extraction.llm_extractor import extract_fuzzy
from src.nlp.messages import RawMention


def _process_article(message: dict[str, Any], sqs_client: Any) -> None:
    article_id = message["article_id"]
    cleaned_text = message.get("cleaned_text") or ""
    title = message.get("title") or ""
    published_at = message.get("published_at") or ""

    deterministic_mentions = extract_deterministic(cleaned_text, article_id=article_id)

    fuzzy_mentions: list[RawMention] = []
    try:
        fuzzy_mentions = extract_fuzzy(cleaned_text, title)
    except Exception:
        # FR-EX-09: graceful degradation -- an LLM failure (timeout, rate
        # limit, outage) must never lose the article. Continue with only
        # the deterministic mentions; no exception escapes the handler.
        fuzzy_mentions = []

    # Stamp article_id onto fuzzy mentions (extract_fuzzy is a pure function
    # over text/title and does not know the article_id).
    fuzzy_mentions = [
        RawMention(
            article_id=article_id,
            entity_type=m.entity_type,
            surface_text=m.surface_text,
            char_span=m.char_span,
            extraction_confidence=m.extraction_confidence,
            context_snippet=m.context_snippet,
        )
        for m in fuzzy_mentions
    ]

    # FR-EX-11: dedup across the COMBINED set, written generically (not
    # assuming the deterministic/LLM entity-type sets are disjoint, even
    # though in practice cve/ttp/ioc vs threat_actor/malware_family are).
    all_mentions = dedup_within_type(deterministic_mentions + fuzzy_mentions)

    queue_url = get_config("raw_mentions_queue_url")
    sqs_client.send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps(
            {
                "article_id": article_id,
                "title": title,
                "published_at": published_at,
                "mentions": [m.to_dict() for m in all_mentions],
            }
        ),
    )


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """SNS-triggered handler: extract mentions from each Article record.

    Skips any record whose `node_label != "Article"` (forward-compat with
    future non-Article traffic on the same `graph-writes` topic) -- no
    error, just skipped.
    """
    sqs_client = boto3.client("sqs")

    processed = 0
    skipped = 0
    for record in event.get("Records", []):
        message = json.loads(record["Sns"]["Message"])
        if message.get("node_label") != "Article":
            skipped += 1
            continue
        _process_article(message, sqs_client)
        processed += 1

    return {"processed": processed, "skipped": skipped}
