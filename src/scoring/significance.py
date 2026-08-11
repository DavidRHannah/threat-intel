"""The novelty clock (spec D3).

`last_significant_event` is materialized rather than derived, and it is stamped ONLY by
L4's event handler for events L4 considers significant -- a new mention or a new
assertion edge. It is deliberately NOT `last_updated`: routine re-enrichment (NVD's
hourly delta re-touching last_modified_date) would pin a year-old CVE at novelty ~1
forever. `last_updated` is also never written anywhere in this codebase, despite
technical-specification.md §3 declaring it (see §6).
"""

from datetime import datetime

from neo4j import ManagedTransaction

from src.scoring._shared import resolve_key_prop

# Monotonic max, not a plain SET. SNS is at-least-once and unordered, so a redelivered
# older event must never rewind the clock and un-spike an entity's novelty.
#
# The `NOT ... IS :: ZONED DATETIME` arm is not paranoia. Neo4j returns NULL -- not false -- when
# ordering two incomparable temporal types, so against a STRING, a DATE, or a naive
# LOCALDATETIME the `< $at` test is NULL, the CASE falls through to ELSE, and the clock is
# frozen at that value FOREVER, with no error and no log. No CURRENT writer produces such a
# value -- src/collection/rest/abusech.py used to write raw strings into first_seen and was
# fixed in Task 3.5 -- but this guard is not about current writers: a live graph still holds
# whatever earlier builds wrote, and this stamp has no way to distinguish the two. A
# frozen clock is strictly worse than a wrong one: a future DATETIME at least self-heals
# once real time passes. Treating an unusable stored value as overwritable is what makes
# this converge.
_STAMP = """
MATCH (n:{label} {{{key_prop}: $key}})
SET n.last_significant_event = CASE
    WHEN n.last_significant_event IS NULL
      OR NOT n.last_significant_event IS :: ZONED DATETIME
      OR n.last_significant_event < $at
        THEN $at ELSE n.last_significant_event
END
"""


def stamp_significant_event(
    tx: ManagedTransaction, *, label: str, key: str, at: datetime
) -> None:
    """Record that something newsworthy happened to this entity. No-op if it is unknown
    or is not a scored label.

    `at` MUST be timezone-aware. A naive datetime is stored as a LOCALDATETIME, which is
    incomparable with every later zoned stamp -- one naive write would pin the entity's
    clock permanently. Rejecting it here is cheaper than detecting it later.

    Idempotent end to end. The write is monotonic, and `at` is the EVENT's own instant,
    minted once by `publish_graph_write` and carried in the message's `event_time`, so an
    SNS redelivery replays the same instant instead of walking the clock forward. A
    caller that mints its own `datetime.now()` per delivery breaks that -- pass the
    message's timestamp.
    """
    if at.tzinfo is None:
        raise ValueError(f"`at` must be timezone-aware, got naive {at!r}")
    # Both label and key_prop are interpolated into _STAMP, so both must be validated.
    # resolve_key_prop is the single path that does that -- do not re-derive it inline.
    key_prop = resolve_key_prop(label)
    if key_prop is None:
        return
    tx.run(_STAMP.format(label=label, key_prop=key_prop), key=key, at=at).consume()
