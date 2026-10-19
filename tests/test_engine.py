"""The redirect loop and the retry-once request attempt."""

from __future__ import annotations

from http.client import BadStatusLine
from types import SimpleNamespace

import pytest

from xrdhttp import engine


@pytest.mark.parametrize("status", [303, 307])
def test_redirect_engine_preserves_or_discards_body_by_status(status):
    requests = []
    state = engine.Request("PUT", "origin", b"payload")

    def send(request):
        requests.append((request.method, request.url, request.body))
        return SimpleNamespace(status=status if len(requests) == 1 else 200)

    response = engine.redirects(
        state,
        send,
        lambda request, response: "target" if response.status != 200 else None,
        1,
        lambda: RuntimeError("redirect limit"),
    )
    assert response.status == 200
    assert requests == [
        ("PUT", "origin", b"payload"),
        ("GET", "target", None) if status == 303 else ("PUT", "target", b"payload"),
    ]


def test_redirect_budget_has_no_extra_request():
    calls = []

    def send(request):
        calls.append(request.url)
        return SimpleNamespace(status=307)

    with pytest.raises(RuntimeError, match="redirect limit"):
        engine.redirects(
            engine.Request("GET", "origin"),
            send,
            lambda request, response: "target",
            2,
            lambda: RuntimeError("redirect limit"),
        )
    assert calls == ["origin", "target", "target"]


def test_the_adapter_narrows_rights_on_the_shared_request():
    seen = []

    def advance(request, response):
        seen.append((request.credentials, request.relay))
        if request.url == "origin":
            request.credentials = False
            return "elsewhere"
        return None

    engine.redirects(
        engine.Request("GET", "origin"),
        lambda request: SimpleNamespace(status=302),
        advance,
        3,
        lambda: RuntimeError("limit"),
    )
    assert seen == [(True, True), (False, True)]


def test_the_redirect_statuses():
    assert {301, 302, 303, 307, 308} == engine.REDIRECTS
    assert 300 not in engine.REDIRECTS and 304 not in engine.REDIRECTS


@pytest.mark.parametrize("error", [OSError("gone"), BadStatusLine("bad")])
@pytest.mark.parametrize("retry", [False, True])
def test_request_retries_at_most_once_and_closes_every_failed_exchange(error, retry):
    acquired: list[object] = []
    aborted: list[object] = []

    def acquire():
        item = object()
        acquired.append(item)
        return item

    def send(item):
        raise error

    with pytest.raises(ValueError, match="translated") as caught:
        engine.attempt(
            acquire,
            send,
            aborted.append,
            lambda item, error: retry,
            lambda error: ValueError("translated"),
        )
    assert caught.value.__cause__ is error
    assert aborted == acquired
    assert len(acquired) == (2 if retry else 1)


def test_a_retry_that_succeeds_returns_its_result():
    attempts = []

    def send(item):
        attempts.append(item)
        if len(attempts) == 1:
            raise ConnectionResetError("stale keep-alive")
        return "answer"

    result = engine.attempt(
        lambda: len(attempts),
        send,
        lambda item: None,
        lambda item, error: True,
        lambda error: error,
    )
    assert result == "answer" and attempts == [0, 1]


@pytest.mark.parametrize("error", [RuntimeError("callback"), KeyboardInterrupt()])
def test_callback_or_interrupt_is_not_wrapped_or_replayed(error):
    aborted: list[object] = []

    def send(item):
        raise error

    with pytest.raises(type(error)) as caught:
        engine.attempt(
            lambda: "exchange",
            send,
            aborted.append,
            lambda item, error: pytest.fail("must not retry"),
            lambda error: pytest.fail("must not translate"),
        )
    assert caught.value is error
    assert aborted == ["exchange"]


def test_successful_exchange_is_not_aborted():
    assert (
        engine.attempt(
            lambda: "exchange",
            lambda item: item,
            lambda item: pytest.fail("must not abort"),
            lambda item, error: False,
            lambda error: error,
        )
        == "exchange"
    )
