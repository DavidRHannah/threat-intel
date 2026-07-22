"""Shared REST error-classification helper for Category B source normalizers (L1 Task 7).

Every per-source normalizer (NVD — Task 8; CISA KEV, GHSA, OTX, abuse.ch — Task 9) wraps
its HTTP call's response through `handle_response`. It classifies one already-received
response and either returns the parsed body or raises one of three typed exceptions —
it does not itself perform retries, sleeps, or issue HTTP requests; the retry loop
belongs to each caller.

FR-DC-19 (Must): 401/403 -> fire `alert_fn`, raise `NoRetryError` (no retry).
FR-DC-20 (Must): 429 -> respect `Retry-After` if present and parseable, else fall back
to exponential backoff (`base * 2**attempt`), raising `RetryAfterError` either way.
FR-DC-21 (Must): a 200 body that fails a supplied `schema_validator` -> `NoRetryError`
(a shape change is a bug to fix, not a transient failure to retry).
Also (not FR-mandated but needed to complete "success vs. not"): 5xx -> `RetryableError`.
"""

from typing import Any, Callable, Protocol

from src.common.config import get_config


class NoRetryError(Exception):
    """Raised for a response the caller must not retry: 401/403 (FR-DC-19) or a body
    that fails schema validation (FR-DC-21)."""


class RetryableError(Exception):
    """Raised for a 5xx response: a transient server-side failure safe to retry."""


class RetryAfterError(Exception):
    """Raised on 429 (FR-DC-20). Carries the number of seconds the caller must wait
    before retrying, either from the `Retry-After` header or an exponential-backoff
    fallback."""

    def __init__(self, retry_after_seconds: float):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"rate limited; retry after {retry_after_seconds}s")


class _Response(Protocol):
    status_code: int
    headers: dict

    def json(self) -> dict: ...


def _backoff_seconds(attempt: int) -> float:
    base = float(get_config("http_backoff_base_seconds", default="1"))
    return base * (2**attempt)


def handle_response(
    response: _Response,
    *,
    alert_fn: Callable[[Any], None],
    attempt: int = 0,
    schema_validator: Callable[[dict], bool] | None = None,
) -> dict:
    """Classify an already-received REST response and either return its parsed JSON
    body or raise the corresponding typed error.

    Args:
        response: An object with `.status_code`, `.headers` (dict-like, supports
            `.get`), and `.json()` — matches `httpx.Response`/`requests.Response`.
        alert_fn: Called with `response` when a 401/403 fires (FR-DC-19). The caller
            decides what "loud alert" means (SNS publish, log, etc.) — this module
            only guarantees it is invoked exactly once before raising.
        attempt: The current retry attempt number (0-indexed), used only to compute
            the exponential-backoff fallback for a 429 with no `Retry-After` header.
        schema_validator: Optional predicate over the parsed 200 body. If provided and
            it returns falsy, the response is treated as malformed (FR-DC-21).

    Returns:
        The parsed JSON body, for a 200 response that passes `schema_validator` (or
        no validator was given).

    Raises:
        NoRetryError: on 401/403, or on a 200 body failing `schema_validator`.
        RetryAfterError: on 429, carrying `retry_after_seconds`.
        RetryableError: on 5xx.
    """
    status_code = response.status_code

    if status_code in (401, 403):
        alert_fn(response)
        raise NoRetryError(f"authentication/authorization failure (HTTP {status_code})")

    if status_code == 429:
        retry_after_header = response.headers.get("Retry-After")
        retry_after_seconds: float
        if retry_after_header is not None:
            try:
                retry_after_seconds = float(retry_after_header)
            except (TypeError, ValueError):
                retry_after_seconds = _backoff_seconds(attempt)
        else:
            retry_after_seconds = _backoff_seconds(attempt)
        raise RetryAfterError(retry_after_seconds)

    if 500 <= status_code < 600:
        raise RetryableError(f"server error (HTTP {status_code})")

    body = response.json()
    if schema_validator is not None and not schema_validator(body):
        raise NoRetryError("response body failed schema validation")

    return body
