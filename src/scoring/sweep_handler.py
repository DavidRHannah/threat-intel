"""The daily sweep: time-driven recomputes plus the unconditional correctness net.

Every phase is a PURE recompute, so a Step Function retry of a partially-applied batch
is a no-op rather than a double-apply. That is what makes the whole sweep safe to
interrupt and resume at any point.

One invocation = one page. The Step Function loops on `done`, which keeps each Lambda
invocation well inside its timeout regardless of graph size.

PHASE ORDER IS NOT ARBITRARY. `prune_flags` reads both node confidence and edge
confidence, so `confidence_rescan` and `decay` must have finished repairing those before
it decides what to flag; running it first would flag against yesterday's values and then
clear the flags a day later. `PHASES` is the declared order -- drive it from there rather
than restating the list.
"""

from datetime import datetime, timezone
from typing import Any

from src.common.neo4j_driver import get_driver
from src.scoring.confidence import (
    decay_edges_batch,
    flag_pruning_batch,
    rescan_confidence_batch,
)
from src.scoring.knobs import ConfidenceKnobs, RelevanceKnobs, SeverityKnobs
from src.scoring.relevance import rescan_novelty_batch
from src.scoring.severity import rescan_severity_batch

# The one upward-layer import in this codebase (plans/05-interop.md Global Constraints):
# reuses this module's existing paginated-sweep infra rather than duplicating a second
# Step Function. Every other cross-layer interface here is message-based (SNS), not this.
from src.interop.knobs import InteropKnobs
from src.interop.withdrawal import revoke_batch

PHASES: tuple[str, ...] = (
    "severity_rescan",
    "confidence_rescan",
    "novelty",
    "decay",
    "prune_flags",
    "stix_withdrawal",
)

# `prune_flags` runs the node scan first, then the edge scan, distinguished by a prefix
# on the cursor so the Step Function needs only one loop for both.
_EDGE_PHASE_PREFIX = "edges:"


def _batch_size() -> int:
    from src.common.config import get_config

    return int(get_config("sweep_batch_size", default="500"))


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    phase = event.get("phase")
    # The Step Function passes "" rather than null (JsonPath.string_at cannot carry a
    # JSON null), so normalize both to None at the boundary.
    cursor = event.get("cursor") or None
    now = datetime.now(timezone.utc)
    driver = get_driver()
    batch_size = _batch_size()

    with driver.session() as session:
        if phase == "severity_rescan":
            knobs = SeverityKnobs.from_config()
            count, nxt = session.execute_write(
                lambda tx: rescan_severity_batch(
                    tx, cursor=cursor, batch_size=batch_size, knobs=knobs
                )
            )
        elif phase == "confidence_rescan":
            # Takes no knobs: it rebuilds from stored evidence (credibility x
            # extraction_confidence per story cluster, noisy-OR'd), and none of those
            # inputs is tunable.
            count, nxt = session.execute_write(
                lambda tx: rescan_confidence_batch(
                    tx, cursor=cursor, batch_size=batch_size
                )
            )
        elif phase == "novelty":
            knobs = RelevanceKnobs.from_config()
            count, nxt = session.execute_write(
                lambda tx: rescan_novelty_batch(
                    tx, cursor=cursor, batch_size=batch_size, knobs=knobs, now=now
                )
            )
        elif phase == "decay":
            knobs = ConfidenceKnobs.from_config()
            touched, nxt = session.execute_write(
                lambda tx: decay_edges_batch(
                    tx, cursor=cursor, batch_size=batch_size,
                    halflife_days=knobs.decay_halflife_days, now=now,
                )
            )
            count = len(touched)
        elif phase == "prune_flags":
            knobs = ConfidenceKnobs.from_config()
            target = "edges" if (cursor or "").startswith(_EDGE_PHASE_PREFIX) else "nodes"
            raw_cursor = (
                cursor[len(_EDGE_PHASE_PREFIX):] or None
                if target == "edges"
                else cursor
            )
            count, nxt = session.execute_write(
                lambda tx: flag_pruning_batch(
                    tx, cursor=raw_cursor, batch_size=batch_size,
                    knobs=knobs, now=now, target=target,
                )
            )
            if target == "nodes":
                # Node scan exhausted -> hand over to the edge scan rather than finishing.
                nxt = _EDGE_PHASE_PREFIX if nxt is None else nxt
            else:
                nxt = None if nxt is None else _EDGE_PHASE_PREFIX + nxt
        elif phase == "stix_withdrawal":
            interop_knobs = InteropKnobs.from_config()
            count, nxt = session.execute_write(
                lambda tx: revoke_batch(
                    tx, cursor=cursor, batch_size=batch_size,
                    floor=interop_knobs.export_confidence_floor, now=now,
                )
            )
        else:
            raise ValueError(f"unknown sweep phase: {phase!r}")

    # Emit "" rather than null for an exhausted scan, so the Step Function's
    # JsonPath.string_at("$.Payload.cursor") stays type-stable on the final iteration.
    return {"phase": phase, "cursor": nxt or "", "done": nxt is None, "count": count}
