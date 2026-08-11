"""graph-writes SNS publishers.

Every message carries a `message_type` MessageAttribute (technical-specification.md §5).
Subscriptions filter on it, so a publisher that omits the attribute has its messages
silently DROPPED by every filtered subscriber. Publish only through this module.

Three types:
  - `article`    -- node-shaped Article announcements (src/collection/rss/extraction.py,
                    src/collection/rest/ghsa.py); consumed by L2 Extraction.
  - `edge_write` -- relationship writes; consumed by L4 Scoring.
  - `node_write` -- scoring-relevant node property changes; consumed by L4 Scoring.
"""

import json
from datetime import datetime, timezone

import boto3

from src.common.config import get_config

MESSAGE_TYPE_ARTICLE = "article"
MESSAGE_TYPE_EDGE_WRITE = "edge_write"
MESSAGE_TYPE_NODE_WRITE = "node_write"


def message_attributes(message_type: str) -> dict:
    """The MessageAttributes block every graph-writes publish must include."""
    return {"message_type": {"DataType": "String", "StringValue": message_type}}


def publish_graph_write(
    *,
    rel_type: str,
    start_key: dict,
    end_key: dict,
    outcome: str,
    origin: str | None = None,
    start_label: str | None = None,
    end_label: str | None = None,
    event_time: datetime | None = None,
) -> None:
    """Announce a relationship write (technical-specification.md §5).

    `start_label`/`end_label` make the message SELF-DESCRIBING. `merge_key` is a
    lowercased normalized NAME whose UNIQUE constraints are PER-LABEL, so a ThreatActor
    and a MalwareFamily may both answer to 'lazarus'; a consumer given the key alone
    cannot tell which entity the edge touched. Every call site already knows the label.

    `event_time` is minted ONCE here, at publish, and travels with the message, so an SNS
    redelivery replays the same instant instead of advancing the consumer's clock. Pass
    the write's own `now` when the caller has one.

    All three are OPTIONAL and additive on purpose: no subscription filter policy
    references them, and L4 falls back to its pre-existing behaviour when they are
    absent, so this deploys in either order with no silent-drop hazard.
    """
    topic_arn = get_config("graph_writes_topic_arn")
    sns = boto3.client("sns")
    at = event_time if event_time is not None else datetime.now(timezone.utc)
    sns.publish(
        TopicArn=topic_arn,
        MessageAttributes=message_attributes(MESSAGE_TYPE_EDGE_WRITE),
        Message=json.dumps(
            {
                "message_type": MESSAGE_TYPE_EDGE_WRITE,
                "rel_type": rel_type,
                "start_key": start_key,
                "end_key": end_key,
                "outcome": outcome,
                "origin": origin,
                "start_label": start_label,
                "end_label": end_label,
                "event_time": at.isoformat(),
            }
        ),
    )


def publish_node_write(
    *, label: str, key: dict, changed_fields: list[str], origin: str | None = None,
) -> None:
    """Announce a scoring-relevant node property change (L4 severity triggers).

    `changed_fields` lets the consumer skip work: L4 recomputes severity only when the
    change intersects {cvss_score, epss_score, exploited_in_wild}. Publish AFTER the
    transaction commits, so a subscriber that reads the node back sees the new value.

    A bare STRING is rejected loudly rather than published. `changed_fields` reaches L4 as
    `frozenset.intersection(changed_fields)`, and a string is iterable BY CHARACTER, so
    `"cvss_score"` intersects `{"cvss_score", ...}` as `{'c','v','s','_','o','r','e'}` --
    empty. The message would publish cleanly, cost nothing, log nothing, and silently
    never recompute severity; the daily sweep would eventually paper over it. Raising at
    the publisher turns a silent no-op into a caller bug that surfaces immediately.
    """
    if isinstance(changed_fields, str) or not isinstance(changed_fields, (list, tuple, set, frozenset)):
        raise TypeError(
            "changed_fields must be a sequence of property names, not "
            f"{type(changed_fields).__name__} ({changed_fields!r}); a bare string is "
            "consumed character-by-character by L4 and matches nothing"
        )
    topic_arn = get_config("graph_writes_topic_arn")
    sns = boto3.client("sns")
    sns.publish(
        TopicArn=topic_arn,
        MessageAttributes=message_attributes(MESSAGE_TYPE_NODE_WRITE),
        Message=json.dumps(
            {
                "message_type": MESSAGE_TYPE_NODE_WRITE,
                "label": label,
                "key": key,
                # Coerced: a set is a legal argument above but is not JSON-serializable.
                "changed_fields": list(changed_fields),
                "origin": origin,
            }
        ),
    )
