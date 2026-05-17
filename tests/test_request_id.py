"""Request-id middleware coverage.

- Every response carries an X-Request-ID header.
- An inbound X-Request-ID is honored verbatim (caller can correlate
  across services).
- A malformed inbound id (with CRLF / non-printable) is REPLACED with a
  fresh one rather than echoed (defends against log-injection).
"""
from __future__ import annotations

import re

from fastapi.testclient import TestClient

_HEX32 = re.compile(r"^[0-9a-f]{32}$")


def test_response_carries_request_id_header(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    rid = r.headers.get("x-request-id")
    assert rid is not None
    assert _HEX32.match(rid), f"expected uuid4 hex, got {rid!r}"


def test_inbound_request_id_is_honored(client: TestClient) -> None:
    r = client.get("/healthz", headers={"X-Request-ID": "trace-abc-123"})
    assert r.status_code == 200
    assert r.headers["x-request-id"] == "trace-abc-123"


def test_malformed_inbound_request_id_replaced(client: TestClient) -> None:
    """A header with CRLF or other unprintables would be a log-injection
    vector if echoed; the middleware drops it and generates a fresh one."""
    # \r and \n forbidden by the validator regex.
    r = client.get("/healthz", headers={"X-Request-ID": "evil\r\nInjected"})
    assert r.status_code == 200
    out = r.headers["x-request-id"]
    assert "\r" not in out and "\n" not in out
    assert _HEX32.match(out), f"expected fresh uuid hex, got {out!r}"


def test_get_request_id_outside_request_returns_dash() -> None:
    """The context var defaults to '-' so log lines emitted at boot or in
    background workers don't crash on the format string."""
    from app.request_id import get_request_id
    assert get_request_id() == "-"
