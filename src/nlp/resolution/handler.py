"""Resolution Lambda handler (Phase 2, Step 2.4 of `plans/02-nlp.md`,
FR-RES-11, FR-RES-12).

Consumes `RawMention[]` per article from the `raw-mentions` SQS queue
(standard SQS Lambda event shape; message body matches what
`src/nlp/extraction/handler.py::_process_article` sends:
`{"article_id": ..., "mentions": [RawMention.to_dict(), ...]}`), dispatches
each mention to the matching `resolve_*` function, retracts stale
deterministic-type `MENTIONS` edges on reprocessing (fuzzy-type mentions are
additive-only -- FR-RES-11), and publishes the resulting `ResolvedArticle` to
the `resolved-articles` SQS queue plus a `graph-writes` SNS notification per
resolved mention.

The raw-mentions message carries `article_id`, `title`, `published_at` (both
threaded through by `src/nlp/extraction/handler.py` from the L1 `graph-writes`
SNS message it consumed) plus `mentions`. `source_id` is recoverable via
`article_ref_from_id` (article_id IS the synthetic `source_guid_key`).
`title`/`published_at` are read straight off the incoming message -- a
missing key falls back to `""` only for defensive robustness (e.g. a
malformed/older message), not because Extraction is expected to omit them.
"""

from __future__ import annotations

import json
from typing import Any

import anthropic
import boto3

from src.common.config import get_config
from src.common.graph.publish import publish_graph_write
from src.common.neo4j_driver import get_driver
from src.nlp.messages import RawMention, ResolvedArticle, ResolvedEntity
from src.nlp.resolution._shared import article_ref_from_id
from src.nlp.resolution.deterministic import resolve_cve, resolve_ioc, resolve_ttp
from src.nlp.resolution.fuzzy import resolve_fuzzy

# Deterministic types get stale-mention retraction (FR-RES-11); fuzzy types
# (threat_actor/malware_family) are additive-only and never retracted.
_DETERMINISTIC_LABEL_BY_TYPE = {"cve": "CVE", "ttp": "TTP", "ioc": "IOC"}
_DETERMINISTIC_KEY_PROP_BY_TYPE = {
    "cve": "cve_id", "ttp": "technique_id", "ioc": "value_type_key",
}
_FUZZY_TYPES = {"threat_actor", "malware_family"}


def _entity_key(entity_type: str, canonical_node_key: str) -> dict:
    if entity_type in _DETERMINISTIC_KEY_PROP_BY_TYPE:
        return {_DETERMINISTIC_KEY_PROP_BY_TYPE[entity_type]: canonical_node_key}
    return {"merge_key": canonical_node_key}


def _resolve_one(driver: Any, get_llm_client: Any, mention: RawMention) -> ResolvedEntity | None:
    if mention.entity_type == "cve":
        return resolve_cve(driver, mention)
    if mention.entity_type == "ttp":
        return resolve_ttp(driver, mention)
    if mention.entity_type == "ioc":
        return resolve_ioc(driver, mention)
    if mention.entity_type in _FUZZY_TYPES:
        # Lazily create/fetch the Anthropic client: an article with only
        # deterministic mentions should never require `anthropic_api_key`
        # config to be present.
        return resolve_fuzzy(driver, mention, get_llm_client())
    return None  # unrecognized entity_type: skip, don't fail the whole article


def _retract_stale_deterministic_mentions(
    driver: Any, article_id: str, current_keys_by_type: dict[str, set[str]]
) -> None:
    def _tx(tx):
        for entity_type, label in _DETERMINISTIC_LABEL_BY_TYPE.items():
            key_prop = _DETERMINISTIC_KEY_PROP_BY_TYPE[entity_type]
            tx.run(
                f"MATCH (:Article {{source_guid_key: $article_id}})-[r:MENTIONS]->(e:{label}) "
                f"WHERE NOT e.{key_prop} IN $keep "
                "DELETE r",
                article_id=article_id,
                keep=list(current_keys_by_type[entity_type]),
            ).consume()

    with driver.session() as session:
        session.execute_write(_tx)


def _process_article(
    message: dict[str, Any], sqs_client: Any, driver: Any, get_llm_client: Any
) -> None:
    article_id = message["article_id"]
    mentions = [RawMention.from_dict(m) for m in message.get("mentions", [])]

    resolved_entities: list[ResolvedEntity] = []
    current_deterministic_keys: dict[str, set[str]] = {t: set() for t in _DETERMINISTIC_LABEL_BY_TYPE}

    for mention in mentions:
        resolved = _resolve_one(driver, get_llm_client, mention)
        if resolved is None:
            continue

        resolved_entities.append(resolved)

        if resolved.resolution_status == "rejected":
            continue  # FR-RES-07: no edge, nothing to retract-track, nothing to publish

        if mention.entity_type in current_deterministic_keys:
            current_deterministic_keys[mention.entity_type].add(resolved.canonical_node_key)

        publish_graph_write(
            rel_type="MENTIONS",
            start_key=article_ref_from_id(article_id),
            end_key=_entity_key(mention.entity_type, resolved.canonical_node_key),
            outcome=resolved.resolution_status,
            origin="resolution",
        )

    # FR-RES-11: retract deterministic-type MENTIONS absent from the new set;
    # fuzzy-type mentions are additive-only and are never retracted here.
    _retract_stale_deterministic_mentions(driver, article_id, current_deterministic_keys)

    resolved_article = ResolvedArticle(
        article_id=article_id,
        title=message.get("title", ""),
        published_at=message.get("published_at", ""),
        source_id=article_ref_from_id(article_id)["source_id"],
        resolved_entities=resolved_entities,
    )

    queue_url = get_config("resolved_articles_queue_url")
    sqs_client.send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps(resolved_article.to_dict()),
    )


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    sqs_client = boto3.client("sqs")
    driver = get_driver()

    _llm_client_cache: dict[str, Any] = {}

    def _get_llm_client() -> Any:
        if "client" not in _llm_client_cache:
            _llm_client_cache["client"] = anthropic.Anthropic(
                api_key=get_config("anthropic_api_key")
            )
        return _llm_client_cache["client"]

    processed = 0
    for record in event.get("Records", []):
        message = json.loads(record["body"])
        _process_article(message, sqs_client, driver, _get_llm_client)
        processed += 1

    return {"processed": processed}
