"""Per-IP rate limiting for abuse-sensitive endpoints.

Two endpoints are decorated today:
  - POST /v1/check    (license probe; 60/min/IP)
  - POST /admin/login (bearer brute-force defense; 10/min/IP)

Why slowapi: it's the FastAPI-flavored wrapper over the `limits` library;
in-memory storage is the default, which is the right fit for our single-VM
deploy. If/when we go multi-instance, swap `storage_uri` to Redis without
touching call sites.

IP-key derivation: request.client.host only — no XFF parsing. Caddy on
loopback means request.client.host IS the last-hop IP set by the proxy.

Don't apply these limiters to the JSON admin API (/v1/admin/*): it's already
behind a 32-byte bearer token with constant-time compare, and rate-limiting
there is friction without security gain (a client app legitimately bursts
when an operator backfills via a script).
"""
from __future__ import annotations

from fastapi import Request
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.responses import JSONResponse


def client_ip(request: Request) -> str:
    """Rate-limit key. Mirrors _client_ip_hash in app.routers.api:
    request.client.host only — no XFF parsing. Caddy on loopback means
    request.client.host IS the last-hop IP. Any future multi-hop deploy
    should re-introduce a trusted-proxies-aware reader here AND in api.py
    together so the two derivations don't drift."""
    if request.client is None:
        return get_remote_address(request)
    return request.client.host


# headers_enabled=False because slowapi's injector only works when the
# endpoint takes (or returns) a starlette Response, and our /v1/check
# returns a pydantic model. The 429 response itself still carries
# `Retry-After` via slowapi's exception handler -- which is what callers
# actually need.
limiter = Limiter(key_func=client_ip, headers_enabled=False)


def rate_limit_exceeded_handler(_request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Return a JSON 429 with the limit string in `detail` so the caller has
    something actionable to log. slowapi's default handler returns
    `text/plain`; JSON keeps parity with the rest of our API errors."""
    return JSONResponse(
        status_code=429,
        content={"code": "rate_limited", "detail": f"rate limit exceeded: {exc.detail}"},
    )
