"""Per-IP rate limiting for abuse-sensitive endpoints.

Two endpoints are decorated today:
  - POST /v1/check    (license probe; 60/min/IP)
  - POST /admin/login (bearer brute-force defense; 10/min/IP)

Why slowapi: it's the FastAPI-flavored wrapper over the `limits` library;
in-memory storage is the default, which is the right fit for our single-VM
deploy. If/when we go multi-instance, swap `storage_uri` to Redis without
touching call sites.

IP-key derivation: we reuse the same loopback-aware XFF logic as
`_client_ip_hash` in [app.routers.api]. Caddy sits on 127.0.0.1 in our
deploy, so the immediate peer is always loopback in prod, and we trust the
leftmost `X-Forwarded-For` entry. Direct (non-Caddy) hits, which shouldn't
happen in prod but might in dev, fall back to the socket peer.

Don't apply these limiters to the JSON admin API (/v1/admin/*): it's already
behind a 32-byte bearer token with constant-time compare, and rate-limiting
there is friction without security gain (ASM legitimately bursts when an
operator backfills via a script).
"""
from __future__ import annotations

from fastapi import Request
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.responses import JSONResponse


def client_ip(request: Request) -> str:
    """Return the originating IP for rate-limit keying. Honors leftmost
    X-Forwarded-For only when the immediate peer is loopback (Caddy on the
    same VM). Mirrors `_client_ip_hash` in app.routers.api so the two
    derivations don't drift."""
    if request.client is None:
        return get_remote_address(request)
    peer = request.client.host
    if peer in ("127.0.0.1", "::1") and "x-forwarded-for" in request.headers:
        xff = request.headers["x-forwarded-for"]
        first = next((p.strip() for p in xff.split(",") if p.strip()), None)
        if first:
            return first
    return peer


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
