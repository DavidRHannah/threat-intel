"""RSS/Atom Extraction Lambda (L1 Task 5).

Consumes `discovery-updates` SQS events (Task 4's poller payload), fetches
each article's full text, `MERGE`s an `Article` node into Neo4j keyed on the
computed synthetic `source_guid_key` (never the raw `(source_id, guid)`
pair — Neo4j `UNIQUE` constraints ignore nulls, so a MERGE on the raw pair
would carry no uniqueness at all), and announces the write on the
`graph-writes` SNS topic so L2's Extraction (NER) Lambda can pick it up.

FR-DC-12 (Must): full-text extraction of the fetched page.
FR-DC-13 (Must): a permanently-failing fetch never drops the article — it
falls back to the discovery event's own `summary` as `cleaned_text`, flagged
`is_fallback_content = True`.
FR-DC-01 (Must, for Article): the MERGE is keyed on `source_guid_key`, so
re-processing the same discovery event (at-least-once delivery) updates the
same node in place rather than creating a duplicate.

Reconciled with L3 (see `.superpowers/sdd/task-5-brief.md`): the SNS
announcement here is a **deliberately hand-rolled**, node-shaped
`sns.publish` — NOT `src.common.graph.publish.publish_graph_write`, which
emits an edge-shaped message L2's Extraction Lambda cannot consume (it
filters on `node_label == "Article"` and reads `cleaned_text`/`title`
straight off the message body, since it is structurally forbidden from
reading Neo4j itself — FR-EX-12). The topic ARN is still resolved via
`get_config("graph_writes_topic_arn")`, the same source `publish_graph_write`
uses — never a hardcoded ARN or region.

Also hand-rolled but NOT optional: the `message_type` MessageAttribute (`"article"`,
`src.common.graph.publish.MESSAGE_TYPE_ARTICLE`). L4's Scoring subscription filters on
this attribute; a publisher that omits it has every message silently dropped by any
filtered subscriber, with no error, no DLQ, and no log (technical-specification.md §5).

All external seams (the page fetch and the SNS client) are injected
parameters so tests drive this module with fakes rather than monkeypatching
`trafilatura`/`boto3`.
"""

import hashlib
import json
from typing import Any, Callable

from src.common import natural_keys
from src.common.config import get_config
from src.common.graph.publish import MESSAGE_TYPE_ARTICLE, message_attributes
from src.common.neo4j_driver import get_driver


def _default_fetch_page(url: str) -> str:
    """Fetch and extract the full cleaned text of `url` via trafilatura. Raises
    on any failure (fetch or extraction) so `_fetch_with_retry` can retry/fall
    back — never returns an empty/None result silently."""
    import trafilatura

    downloaded = trafilatura.fetch_url(url)
    if downloaded is None:
        raise ValueError(f"trafilatura.fetch_url returned no content for {url!r}")
    extracted = trafilatura.extract(downloaded)
    if not extracted:
        raise ValueError(f"trafilatura.extract returned no content for {url!r}")
    return extracted


def _fetch_with_retry(
    url: str,
    fetch_page_fn: Callable[[str], str],
    attempt_cap: int,
) -> tuple[str | None, bool]:
    """Try `fetch_page_fn(url)` up to `attempt_cap` times. Returns
    (cleaned_text, is_fallback_content). On permanent failure (every attempt
    raises), returns (None, True) so the caller falls back to the event's own
    summary (FR-DC-13) — the article is never dropped."""
    for _attempt in range(attempt_cap):
        try:
            return fetch_page_fn(url), False
        except Exception:  # noqa: BLE001 - any fetch/extraction failure is retryable
            continue
    return None, True


def _content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def process_discovery_event(
    payload: dict,
    *,
    fetch_page_fn: Callable[[str], str],
    sns_client: Any,
    driver: Any,
    topic_arn: str,
    attempt_cap: int,
) -> None:
    """Process one discovery/update event: fetch full text (with fallback),
    MERGE the Article node, and publish the node-shaped SNS announcement."""
    source_id = payload["source_id"]
    guid = payload["guid"]
    title = payload.get("title", "")
    summary = payload.get("summary", "")
    link = payload.get("link", "")
    published_at = payload.get("published_at")
    fetched_at = payload.get("fetched_at")

    cleaned_text, is_fallback_content = _fetch_with_retry(link, fetch_page_fn, attempt_cap)
    if cleaned_text is None:
        # FR-DC-13: permanent failure falls back to the feed's own summary.
        # The Article is ALWAYS created — never dropped.
        cleaned_text = summary

    source_guid_key = natural_keys.article_key(source_id, guid)
    content_hash = _content_hash(cleaned_text)

    with driver.session() as session:
        session.execute_write(
            _merge_article_tx,
            source_guid_key=source_guid_key,
            source_id=source_id,
            guid=guid,
            title=title,
            url=link,
            cleaned_text=cleaned_text,
            summary=summary,
            content_hash=content_hash,
            published_at=published_at,
            fetched_at=fetched_at,
            is_fallback_content=is_fallback_content,
        )

    # Node-shaped announcement for L2's Extraction (NER) Lambda — deliberately
    # NOT publish_graph_write (see module docstring). article_id IS
    # source_guid_key: the Article has no separate id in the schema.
    sns_client.publish(
        TopicArn=topic_arn,
        MessageAttributes=message_attributes(MESSAGE_TYPE_ARTICLE),
        Message=json.dumps(
            {
                "message_type": MESSAGE_TYPE_ARTICLE,
                "node_label": "Article",
                "article_id": source_guid_key,
                "source_id": source_id,
                "guid": guid,
                "cleaned_text": cleaned_text,
                "title": title,
                "published_at": published_at,
            }
        ),
    )


def _merge_article_tx(tx: Any, **props: Any) -> None:
    source_guid_key = props.pop("source_guid_key")
    tx.run(
        """
        MERGE (a:Article {source_guid_key: $source_guid_key})
        ON CREATE SET a.dedup_cluster_size = 1
        SET a += $props
        """,
        source_guid_key=source_guid_key,
        props=props,
    ).consume()


def handler(
    event: dict,
    context: Any,
    *,
    fetch_page_fn: Callable[[str], str] | None = None,
    sns_client: Any = None,
) -> dict:
    """Lambda entry point. Relies on the Lambda's ambient AWS region — never a
    hardcoded one (NFR-MAINT-01)."""
    if fetch_page_fn is None:
        fetch_page_fn = _default_fetch_page
    if sns_client is None:
        import boto3

        sns_client = boto3.client("sns")

    topic_arn = get_config("graph_writes_topic_arn")
    attempt_cap = int(get_config("extraction_attempt_cap", default="3"))
    driver = get_driver()

    processed = 0
    for record in event.get("Records", []):
        payload = json.loads(record["body"])
        process_discovery_event(
            payload,
            fetch_page_fn=fetch_page_fn,
            sns_client=sns_client,
            driver=driver,
            topic_arn=topic_arn,
            attempt_cap=attempt_cap,
        )
        processed += 1
    return {"processed": processed}
