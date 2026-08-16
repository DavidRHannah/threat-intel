"""One-shot NVD backfill for CVE nodes that no NVD read has ever touched.

CISA KEV, GHSA and OTX MERGE bare `cve_id` stubs when they reference a CVE the graph has
not seen (FR-DC-22), and the scheduled delta poll only revisits CVEs NVD itself modified
inside the poll window (FR-DC-17, FR-DC-23). Nothing closes the gap between the two: a
stub for a CVE NVD has not touched since it was created is never enriched by anything.
In the live graph that left 1667 of 1735 CVEs with no description, no CVSS, no CWE and no
`affected_products` — which in turn left `severity_score` resting almost entirely on the
KEV floor with no real impact term behind it.

This module is the catch-up pass. It is deliberately NOT a Lambda: it runs once (plus
whenever stubs accumulate again), it needs to outlive a 15-minute Lambda timeout on the
keyless rate limit, and the recurring freshness job it complements already exists. The
thin CLI wrapper is `scripts/run_nvd_backfill.py`.

Resumability comes from the graph rather than a checkpoint file: the work list is derived
fresh on every run, so a crashed run resumes simply by being run again, and a completed
run is a no-op.
"""

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from src.collection.rest.http_errors import RetryableError, RetryAfterError
from src.collection.rest.nvd import enrich_cve

# NVD's documented public limits, per the rolling window they describe:
# 5 requests / 30s without an API key, 50 / 30s with one.
NVD_WINDOW_SECONDS = 30.0
NVD_REQUESTS_PER_WINDOW_KEYLESS = 5
NVD_REQUESTS_PER_WINDOW_WITH_KEY = 50

# One request short of the documented ceiling. The limit is enforced server-side against
# NVD's clock, not ours, and a run pinned exactly at the ceiling trips 429s on ordinary
# clock skew — which costs more time in backoff than the request we gave up.
_HEADROOM = 1


class _HttpClient(Protocol):
    def get(self, url: str, params: dict | None = None) -> Any: ...


@dataclass
class BackfillResult:
    """Counts for one run. `attempted` is the size of the work list this run consumed."""

    attempted: int = 0
    enriched: int = 0
    not_found: int = 0


class RateLimiter:
    """Token bucket over a rolling window, matching how NVD enforces its limit.

    A fixed per-request delay would be wrong in both directions: too slow across the
    window as a whole, and still burst-prone at a window boundary. This tracks the
    timestamps of the last `requests_per_window` acquisitions and, when the window is
    full, sleeps out the remainder of the OLDEST one.

    `sleep`/`monotonic` are injectable so the policy is testable without real time.
    """

    def __init__(
        self,
        requests_per_window: int,
        window_seconds: float = NVD_WINDOW_SECONDS,
        *,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if requests_per_window < 1:
            raise ValueError("requests_per_window must be >= 1")
        self._limit = requests_per_window
        self._window = window_seconds
        self._sleep = sleep
        self._monotonic = monotonic
        self._recent: list[float] = []

    @property
    def seconds_per_request(self) -> float:
        """Sustained cost of one request, for runtime estimates."""
        return self._window / self._limit

    def acquire(self) -> None:
        now = self._monotonic()
        self._recent = [t for t in self._recent if now - t < self._window]
        if len(self._recent) >= self._limit:
            wait = self._window - (now - self._recent[0])
            if wait > 0:
                self._sleep(wait)
                now = self._monotonic()
                self._recent = [t for t in self._recent if now - t < self._window]
        self._recent.append(now)


def rate_limiter_for(*, has_api_key: bool, **kwargs) -> RateLimiter:
    """The limiter matching NVD's tier for this run. 5/30s keyless vs 50/30s with a key
    is the difference between roughly three hours and roughly twenty minutes over the
    live backlog."""
    limit = (
        NVD_REQUESTS_PER_WINDOW_WITH_KEY if has_api_key else NVD_REQUESTS_PER_WINDOW_KEYLESS
    ) - _HEADROOM
    return RateLimiter(limit, **kwargs)


# `last_modified_date` is written only by `_apply_cve_tx`'s re-sync branch, so its
# absence is an exact marker for "no NVD read has ever landed on this node". Ordering is
# newest-id-first so a partial run covers the CVEs most likely to matter today, and so a
# --limit run is reproducible rather than arbitrary.
# Task 3: also re-touch CVEs that were enriched before CPEMatch existed (have
# last_modified_date but zero MATCHES edges).
_WORK_LIST = """
MATCH (c:CVE)
WHERE c.nvd_not_found_at IS NULL
  AND (c.last_modified_date IS NULL OR NOT EXISTS { (c)-[:MATCHES]->(:CPEMatch) })
RETURN c.cve_id AS cve_id
ORDER BY c.cve_id DESC
"""

_MARK_NOT_FOUND = "MATCH (c:CVE {cve_id:$id}) SET c.nvd_not_found_at = $at"


def find_unenriched_cve_ids(driver, *, limit: int | None = None) -> list[str]:
    """Every CVE node NVD has never enriched, minus those NVD has no record of."""
    query = _WORK_LIST if limit is None else f"{_WORK_LIST}LIMIT $limit"
    with driver.session() as session:
        return [r["cve_id"] for r in session.run(query, limit=limit)]


def mark_not_found(driver, cve_id: str, *, now: datetime | None = None) -> None:
    """Record that NVD returned no record for this CVE, excluding it from future runs.

    Deliberately a separate property rather than a sentinel `last_modified_date`: the
    latter is the CATEGORIZED_AS freshness watermark, and writing a fake value into it
    would suppress a real re-sync if NVD later publishes the CVE.
    """
    at = (now or datetime.now(timezone.utc)).isoformat()
    with driver.session() as session:
        session.run(_MARK_NOT_FOUND, id=cve_id, at=at).consume()


def backfill(
    driver,
    http_client: _HttpClient,
    *,
    rate_limiter: RateLimiter | None,
    limit: int | None = None,
    publish: bool = False,
    max_attempts: int = 5,
    sleep: Callable[[float], None] = time.sleep,
    on_progress: Callable[[int, int, str], None] | None = None,
) -> BackfillResult:
    """Enrich every never-enriched CVE, one NVD request each.

    Retries only what is genuinely transient — 429 (honouring `Retry-After`) and 5xx.
    `NoRetryError` propagates and ABORTS the run rather than being recorded per-CVE:
    `handle_response` raises it for a 403 (a bad or missing API key) with the same
    exception class as any other unrecoverable 4xx, so swallowing it would stamp
    `nvd_not_found_at` across the entire work list and permanently exclude every CVE in
    it. A run that dies loudly on request one is recoverable; one that quietly poisons
    the work list is not.

    `publish` defaults to False here, the inverse of `enrich_cve`'s own default: a
    backfill is a bulk historical catch-up, and announcing thousands of CVSS changes
    would fan out to L4's per-message Lambda with no reserved concurrency against an
    AuraDB Free connection cap. The daily scoring sweep picks these up regardless.
    """
    cve_ids = find_unenriched_cve_ids(driver, limit=limit)
    result = BackfillResult(attempted=len(cve_ids))

    for index, cve_id in enumerate(cve_ids, start=1):
        applied = _enrich_with_retries(
            driver,
            http_client,
            cve_id,
            rate_limiter=rate_limiter,
            max_attempts=max_attempts,
            sleep=sleep,
            publish=publish,
        )
        if applied:
            result.enriched += 1
        else:
            mark_not_found(driver, cve_id)
            result.not_found += 1
        if on_progress is not None:
            on_progress(index, result.attempted, cve_id)

    return result


def _enrich_with_retries(
    driver,
    http_client: _HttpClient,
    cve_id: str,
    *,
    rate_limiter: RateLimiter | None,
    max_attempts: int,
    sleep: Callable[[float], None],
    publish: bool,
) -> bool:
    last_error: Exception | None = None
    for attempt in range(max_attempts):
        if rate_limiter is not None:
            rate_limiter.acquire()
        try:
            return enrich_cve(driver, http_client, cve_id, publish=publish)
        except RetryAfterError as exc:
            last_error = exc
            sleep(exc.retry_after_seconds)
        except RetryableError as exc:
            last_error = exc
            sleep(2.0**attempt)
    raise RuntimeError(
        f"{cve_id}: giving up after {max_attempts} attempts"
    ) from last_error
