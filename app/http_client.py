"""Outbound HTTP transport.

Single shared `httpx.Client` for every outbound call (webhooks, email
provider, anything else added later). Centralizing it gives us:

- one place that disables `follow_redirects` so a malicious receiver can't
  bounce us to a metadata endpoint via a 302 (M9 in the v0.7 review)
- one shared timeout/connection-pool config
- one swap-point for tests: `set_client(httpx.Client(transport=MockTransport))`
  so the assertion machinery doesn't need to monkeypatch urllib globals

Sync client only -- FastAPI's outbound paths from sync handlers are sync too,
and webhook delivery moves to BackgroundTasks (Phase 4) which keeps the
request thread free without needing AsyncClient gymnastics.
"""
from __future__ import annotations

from typing import Final

import httpx

DEFAULT_TIMEOUT: Final = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)

_client: httpx.Client | None = None


def _build_default() -> httpx.Client:
    return httpx.Client(
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": "YgLicenseServer/1"},
    )


def get_client() -> httpx.Client:
    """Process-wide singleton. Lazily built on first call."""
    global _client
    if _client is None:
        _client = _build_default()
    return _client


def set_client(c: httpx.Client) -> None:
    """Replace the active client. Used by tests to inject MockTransport.
    Caller owns the lifecycle of `c` (and the prior client if any)."""
    global _client
    _client = c


def reset_client() -> None:
    """Tear down and forget the current client. Tests use this to reset
    state between cases without leaking sockets."""
    global _client
    if _client is not None:
        _client.close()
    _client = None
