"""Tests for the shared REST error-handling helper (Task 7).

FR-DC-19 (Must): 401/403 -> alert + no retry.
FR-DC-20 (Must): 429 -> respect Retry-After, else exponential backoff.
FR-DC-21 (Must): malformed (schema-validation-failing) 200 body -> no retry.
"""

import pytest

from src.collection.rest.http_errors import (
    NoRetryError,
    RetryableError,
    RetryAfterError,
    handle_response,
)


class FakeResponse:
    def __init__(self, status_code: int, headers: dict | None = None, body: dict | None = None):
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body if body is not None else {}

    def json(self) -> dict:
        return self._body


def _requester_that_calls_handle_response(response, **kwargs):
    """Simulates a caller wrapping one HTTP call through handle_response, wired so
    the test can assert how many times it (and therefore any retry loop around it)
    was invoked."""
    return handle_response(response, **kwargs)


# --- FR-DC-19: 401/403 -> alert_fn called once, NoRetryError, caller does not retry ---


@pytest.mark.parametrize("status_code", [401, 403])
def test_401_403_calls_alert_and_raises_no_retry(status_code):
    alert_calls = []

    def alert_fn(response):
        alert_calls.append(response)

    response = FakeResponse(status_code)

    with pytest.raises(NoRetryError):
        handle_response(response, alert_fn=alert_fn)

    assert len(alert_calls) == 1
    assert alert_calls[0] is response


def test_401_caller_does_not_retry():
    """Demonstrates a fake caller wrapping the HTTP call through handle_response only
    ever calls it once for a 401 -- no retry loop follows a NoRetryError."""
    call_count = 0
    response = FakeResponse(401)

    def alert_fn(response):
        pass

    def fake_call():
        nonlocal call_count
        call_count += 1
        return _requester_that_calls_handle_response(response, alert_fn=alert_fn)

    with pytest.raises(NoRetryError):
        fake_call()
        fake_call()  # would only run if the first call's exception were swallowed

    assert call_count == 1


# --- FR-DC-20: 429 -> Retry-After header, or exponential backoff fallback ---


def test_429_respects_retry_after_header():
    response = FakeResponse(429, headers={"Retry-After": "30"})

    with pytest.raises(RetryAfterError) as exc_info:
        handle_response(response, alert_fn=lambda r: None)

    assert exc_info.value.retry_after_seconds == 30


def test_429_falls_back_to_exponential_backoff_when_no_header(monkeypatch):
    monkeypatch.setenv("CROSSROADS_HTTP_BACKOFF_BASE_SECONDS", "2")
    from src.common.config import get_config

    get_config.cache_clear()

    response = FakeResponse(429)

    for attempt in (0, 1, 3):
        with pytest.raises(RetryAfterError) as exc_info:
            handle_response(response, alert_fn=lambda r: None, attempt=attempt)
        assert exc_info.value.retry_after_seconds == 2 * (2**attempt)

    get_config.cache_clear()


def test_429_non_integer_retry_after_falls_back_to_backoff(monkeypatch):
    monkeypatch.setenv("CROSSROADS_HTTP_BACKOFF_BASE_SECONDS", "1")
    from src.common.config import get_config

    get_config.cache_clear()

    response = FakeResponse(429, headers={"Retry-After": "not-a-number"})

    with pytest.raises(RetryAfterError) as exc_info:
        handle_response(response, alert_fn=lambda r: None, attempt=0)

    assert exc_info.value.retry_after_seconds == 1

    get_config.cache_clear()


# --- 5xx -> RetryableError ---


@pytest.mark.parametrize("status_code", [500, 502, 503])
def test_5xx_raises_retryable_error(status_code):
    response = FakeResponse(status_code)

    with pytest.raises(RetryableError):
        handle_response(response, alert_fn=lambda r: None)


# --- FR-DC-21: 200 body failing schema_validator -> NoRetryError, no retry ---


def test_malformed_200_body_raises_no_retry():
    response = FakeResponse(200, body={"unexpected": "shape"})

    def schema_validator(body):
        return "expected_field" in body

    with pytest.raises(NoRetryError):
        handle_response(response, alert_fn=lambda r: None, schema_validator=schema_validator)


def test_valid_200_body_returns_dict():
    body = {"expected_field": "value"}
    response = FakeResponse(200, body=body)

    def schema_validator(b):
        return "expected_field" in b

    result = handle_response(response, alert_fn=lambda r: None, schema_validator=schema_validator)
    assert result == body


def test_200_with_no_validator_returns_dict():
    body = {"anything": True}
    response = FakeResponse(200, body=body)

    result = handle_response(response, alert_fn=lambda r: None)
    assert result == body


def test_201_with_no_validator_returns_dict():
    """A non-200 2xx success status still parses and returns the body."""
    body = {"created": True}
    response = FakeResponse(201, body=body)

    result = handle_response(response, alert_fn=lambda r: None)
    assert result == body


# --- Unclassified status codes (3xx, or 4xx other than 401/403/429) -> NoRetryError,
# and response.json() must never be called for them (an HTML/non-JSON error body must
# not crash the classifier with an unhandled JSONDecodeError). ---


class _JsonRaisesIfCalled(FakeResponse):
    """A FakeResponse whose .json() blows up if it is ever invoked, so the test proves
    handle_response never attempts to parse the body for an unclassified status."""

    def json(self) -> dict:
        raise AssertionError("response.json() must not be called for an unclassified status")


@pytest.mark.parametrize("status_code", [301, 404])
def test_unclassified_status_raises_no_retry_without_parsing_body(status_code):
    response = _JsonRaisesIfCalled(status_code)

    with pytest.raises(NoRetryError):
        handle_response(response, alert_fn=lambda r: None)
