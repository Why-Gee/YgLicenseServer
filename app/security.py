"""Security helpers shared across routers.

Defensive primitives that should not live in any single route handler:

- constant-time bearer-token check (admin auth across both JSON + form paths)
- outbound-URL safety check (SSRF guard for /v1/check's self-registered
  public_url AND for admin-supplied webhook URLs)

Two-tier SSRF model:
- `is_safe_url_shape()` is cheap, no DNS. Used at ingestion time to reject
  obvious literal-IP / *.local / non-http(s) URLs. Doesn't catch a public-DNS
  hostname that resolves privately — that's the next layer's job.
- `is_safe_for_delivery()` does DNS resolution and rejects URLs whose A/AAAA
  records point at any private/loopback/link-local/multicast addr. Run this
  immediately before every outbound HTTP request.
"""
from __future__ import annotations

import hmac
import ipaddress
import logging
import socket
from urllib.parse import urlsplit

log = logging.getLogger("license-server.security")

# Hostnames that always fail the safety check, regardless of DNS resolution.
# *.example / *.test / *.invalid are RFC-reserved and never resolve in prod;
# *.local / *.internal / *.lan / *.intranet / *.corp / *.home / *.private
# are common internal-network suffixes that should never be a webhook target.
_FORBIDDEN_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".lan",
    ".intranet",
    ".corp",
    ".home",
    ".private",
)


def check_admin_bearer(authorization: str | None, admin_token: str) -> bool:
    """Constant-time check of an `Authorization: Bearer <token>` header.

    Returns True iff the header is well-formed AND the token matches. Both
    halves use hmac.compare_digest so we never short-circuit on prefix.
    """
    if not authorization or not admin_token:
        return False
    expected = f"Bearer {admin_token}"
    a = authorization.encode("utf-8", "replace")
    b = expected.encode("utf-8", "replace")
    if len(a) != len(b):
        # still do a compare to keep timing flat
        hmac.compare_digest(b, b)
        return False
    return hmac.compare_digest(a, b)


def _ip_is_private(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_safe_url_shape(url: str, *, allow_http: bool = False) -> bool:
    """Cheap ingestion-time SSRF check. No DNS lookup.

    Rejects:
    - non-http(s) schemes
    - plain http when allow_http=False
    - hostnames that are literal private/loopback/link-local IPs
    - hostnames ending in any forbidden suffix (*.local, *.internal, ...)
    - bare "localhost"

    Returns True for any public-DNS-looking hostname, even if it doesn't
    resolve yet. The delivery-time check (is_safe_for_delivery) is what
    actually enforces "the resolved IP is public" at the point of use.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https"):
        return False
    if parts.scheme == "http" and not allow_http:
        return False
    host = parts.hostname
    if not host:
        return False
    host_l = host.lower()
    if host_l == "localhost" or any(host_l.endswith(s) for s in _FORBIDDEN_HOST_SUFFIXES):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True  # hostname; delivery-time check resolves it
    else:
        return not _ip_is_private(host)


def is_safe_for_delivery(url: str, *, allow_http: bool = False) -> tuple[bool, str | None]:
    """Authoritative SSRF check used right before an outbound request.

    Runs is_safe_url_shape() PLUS DNS resolution of the hostname. If any
    resolved A/AAAA address is private/loopback/link-local/multicast, the
    URL is refused. Returns (ok, reason); reason is None on success and a
    short string on refusal for log lines.
    """
    if not is_safe_url_shape(url, allow_http=allow_http):
        return False, "unsafe_url_shape"
    parts = urlsplit(url)
    host = parts.hostname or ""
    # Literal IP already cleared by is_safe_url_shape; skip the DNS round-trip.
    try:
        ipaddress.ip_address(host)
        return True, None
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as e:
        return False, f"dns_failed:{e.__class__.__name__}"
    for _fam, _t, _p, _c, sockaddr in infos:
        addr = sockaddr[0]
        if _ip_is_private(addr):
            return False, f"resolves_to_private:{addr}"
    return True, None
