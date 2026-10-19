"""Request lifecycle shared by the HTTP facades.

Adapters own credentials, URL spelling, replay policy and numeric errors.
This module owns bounded attempts, redirect iteration and resource cleanup.

Every client's HTTP facade drives it - xrdclient's ``HTTPClient``,
xgfalclient's HTTP plug-in - and each supplies callbacks for the parts that
differ - how a request is put on the wire, what a redirect may still carry
(see :mod:`xrdhttp.redirects`), which error a failure becomes - so that the
two loops that are easy to get subtly wrong are written once. Keep the
decisions here few: every one is a decision in every client.

What a maintainer must not break: a redirect budget of ``limit`` means at
most ``limit + 1`` requests (``tests/test_engine.py`` pins it), a
``303`` turns the request into a bodiless ``GET`` while ``307``/``308``
replay method and body unchanged (RFC 9110 sections 15.4.4, 15.4.8 and
15.4.9), and a request is retried at most once.
"""

from __future__ import annotations

import http.client
from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar

__all__ = ["REDIRECTS", "HTTPResponse", "Request", "attempt", "redirects"]

URL = TypeVar("URL")
Body = TypeVar("Body")
Exchange = TypeVar("Exchange")
Result = TypeVar("Result")
Response = TypeVar("Response", bound="HTTPResponse")

#: The statuses that send a client elsewhere with a ``Location`` (RFC 9110
#: section 15.4). ``300`` (a choice for a human) and ``304`` (a cache
#: answer) are not redirects to follow, and ``305``/``306`` are obsolete.
REDIRECTS = frozenset({301, 302, 303, 307, 308})


class HTTPResponse(Protocol):
    """The one thing the redirect loop reads off a response: its status code."""

    status: int


@dataclass
class Request(Generic[URL, Body]):
    """One request as it travels a redirect chain, rewritten hop by hop.

    ``credentials`` and ``relay`` are rights that only ever narrow along the
    chain: whether the caller's own credentials may still be sent, and
    whether a WLCG ``COPY``'s ``TransferHeader*`` headers may (see
    :func:`xrdhttp.redirects.relays_transfer_headers`). The adapter's
    ``advance`` callback updates them; this module only carries them.
    Mutable on purpose: :func:`redirects` updates ``url``, ``method`` and
    ``body`` in place, and the adapter's callbacks see the same object.
    """

    method: str
    url: URL
    body: Body | None = None
    credentials: bool = True
    relay: bool = True


def redirects(
    request: Request[URL, Body],
    send: Callable[[Request[URL, Body]], Response],
    advance: Callable[[Request[URL, Body], Response], URL | None],
    limit: int,
    exhausted: Callable[[], Exception],
) -> Response:
    """Send ``request``, following redirects, and return the final response.

    ``send`` puts one hop on the wire; ``advance`` reads its response and
    answers the next URL, or ``None`` when that response is the answer (it
    is also where the adapter decides what a redirect means for credentials,
    and must consume the redirect's body). After ``limit`` redirects the
    error ``exhausted()`` builds is raised, without sending another request.
    """
    for _ in range(limit + 1):
        response = send(request)
        target = advance(request, response)
        if target is None:
            return response
        request.url = target
        # RFC 9110 section 15.4.4: 303 See Other is answered with a GET of
        # the new URL. 301 and 302 keep the method: RFC 9110 permits a user
        # agent to turn a redirected POST into a GET, for historical
        # reasons, but does not require it, and a tape REST POST must stay one.
        if response.status == 303:
            request.method, request.body = "GET", None
    raise exhausted()


def attempt(
    acquire: Callable[[], Exchange],
    send: Callable[[Exchange], Result],
    abort: Callable[[Exchange], None],
    retry: Callable[[Exchange, Exception], bool],
    wrap: Callable[[Exception], Exception],
) -> Result:
    """Run ``send`` on a fresh ``acquire()``, retrying once if ``retry`` allows.

    A pooled keep-alive connection may have been closed by the server while
    it sat idle (RFC 9112 section 9.5 lets either side close a connection
    at any time), and the client only finds out when the next request fails.
    One retry on a new exchange covers that; a second failure is real.
    Whether the request is safe to repeat at all (RFC 9112 section 9.3.1:
    not a non-idempotent one) is the adapter's ``retry`` decision. Only
    transport failures (:class:`OSError`, :class:`http.client.HTTPException`)
    are candidates, and they leave as ``wrap(exc)``, chained to the original.
    Anything else - a ``KeyboardInterrupt``, a cancellation - still aborts
    the exchange, so a half-used connection never goes back into a pool, and
    propagates as is.
    """
    retried = False
    while True:
        exchange = acquire()
        try:
            return send(exchange)
        except (OSError, http.client.HTTPException) as exc:
            abort(exchange)
            if not retried and retry(exchange, exc):
                retried = True
                continue
            raise wrap(exc) from exc
        except BaseException:
            abort(exchange)
            raise
