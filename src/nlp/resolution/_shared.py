"""Internal helpers shared across the Resolution stage's modules.

Not a public stage entry point itself.
"""

from __future__ import annotations


def article_ref_from_id(article_id: str) -> dict:
    """Recover the raw `(source_id, guid)` pair `write_mentions_edge` needs.

    Resolution's SQS input (`{"article_id": ..., "mentions": [...]}`, per
    `src/nlp/extraction/handler.py::_process_article`) carries only the
    already-computed synthetic `article_id`, which IS
    `natural_keys.article_key(source_id, guid)` == f"{source_id}::{guid}"
    (see `src/collection/rss/extraction.py`'s comment: "article_id IS
    source_guid_key: the Article has no separate id in the schema"). Nothing
    downstream of Extraction ever carries `source_id`/`guid` separately.

    `source_id` values are simple config slugs (`nvd-cve`, `ghsa`,
    `cisa-kev`, ...) that never contain the literal "::" separator, so
    splitting on the FIRST "::" exactly inverts the f"{source_id}::{guid}"
    join even when `guid` itself contains further "::" occurrences (e.g. a
    URL guid with a doubled colon-slash sequence).
    """
    source_id, _, guid = article_id.partition("::")
    return {"source_id": source_id, "guid": guid}
