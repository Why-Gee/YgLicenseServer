"""Request-ID propagation across the request lifecycle.

A single `contextvars.ContextVar` carries the current request id wherever
it's read: log records, service-layer logging, background tasks scheduled
from a handler. Combined with a log filter that injects the id into the
record, every line emitted during one request is greppable by that id.

Convention:
- Incoming `X-Request-ID` header is honored verbatim. Caddy/Cloudflare in
  the deploy front sets this; honoring it lets us join logs across the LB.
- Missing or malformed -> we generate a fresh UUID4 hex.
- Response always carries `X-Request-ID` so the client can log the id and
  correlate when they raise an issue.

The context var defaults to "-" so log lines emitted OUTSIDE any request
(boot, scheduled tasks that don't carry the context) still format cleanly.
"""
from __future__ import annotations

import logging
import re
import uuid
from contextvars import ContextVar

from starlette.types import ASGIApp, Receive, Scope, Send

_REQUEST_ID: ContextVar[str] = ContextVar("request_id", default="-")

# Match a printable, non-whitespace token up to 128 chars. Defends against a
# header injection that tries to smuggle CRLF into log lines or response
# headers; anything that doesn't match falls through to UUID generation.
_VALID_ID = re.compile(r"^[A-Za-z0-9._\-:]{1,128}$")


def get_request_id() -> str:
    """Current request id, or '-' outside any request."""
    return _REQUEST_ID.get()


def _new_id() -> str:
    return uuid.uuid4().hex


class RequestIdMiddleware:
    """ASGI middleware. Reads / generates the id, stores it on the context
    var for the duration of the request, sets `X-Request-ID` on the response.

    Implemented at ASGI level (not as a BaseHTTPMiddleware) so the context
    var assignment lives inside the same task that runs the handler --
    Starlette's BaseHTTPMiddleware spawns a separate task and contextvars
    don't propagate across that boundary.
    """

    def __init__(self, app: ASGIApp, header_name: str = "x-request-id") -> None:
        self.app = app
        self._header = header_name.lower().encode("ascii")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        # Find an inbound id; validate or replace.
        rid: str | None = None
        for name, value in scope.get("headers", []):
            if name == self._header:
                try:
                    s = value.decode("latin-1").strip()
                except UnicodeDecodeError:
                    s = ""
                if _VALID_ID.match(s):
                    rid = s
                break
        if rid is None:
            rid = _new_id()

        token = _REQUEST_ID.set(rid)
        header_pair = (self._header, rid.encode("ascii"))

        async def _send(message):
            # Stamp every response (start message) with the id. WebSocket
            # accept frames also carry headers, so we handle both shapes.
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                # Replace any existing X-Request-ID rather than appending a dup.
                headers = [(n, v) for (n, v) in headers if n != self._header]
                headers.append(header_pair)
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, _send)
        finally:
            _REQUEST_ID.reset(token)


class RequestIdLogFilter(logging.Filter):
    """Injects `request_id` onto every LogRecord so a format string with
    `%(request_id)s` resolves. Records emitted outside a request show '-'."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _REQUEST_ID.get()
        return True
