"""Security helpers shared across routers.

Defensive primitives that should not live in any single route handler:

- constant-time bearer-token check (admin auth across both JSON + form paths)
- outbound-URL safety check (SSRF guard for /v1/check's self-registered
  public_url AND for admin-supplied webhook URLs)
- CSRF token derived deterministically from the admin session cookie

Three-tier SSRF model:
- `is_safe_url_shape()` — cheap, no DNS. Ingestion-time gate that rejects
  obvious literal-IP / *.local / non-http(s) URLs. Doesn't catch a public-DNS
  hostname that resolves privately — that's the next layer's job.
- `resolve_safe_address()` — delivery-time, authoritative outbound guard.
  Resolves the hostname once, refuses if any resolved address is private, and
  returns the literal IP so the caller can pin the connection (no re-resolve
  at connect time). This is the function called right before every webhook
  delivery; it closes the DNS-rebinding TOCTOU that a simple DNS check leaves
  open.
- `is_safe_for_delivery()` — legacy diagnostic helper. Retained for boot-time
  URL validation (config self-check) and troubleshooting. No longer called
  from the delivery path; `resolve_safe_address` supersedes it there.
"""
from __future__ import annotations

import hashlib
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


def csrf_token(session_secret: str, session_cookie: str) -> str:
    """Deterministic CSRF token tied to a specific session cookie.

    Derived as HMAC(session_secret, "csrf:" + session_cookie). Doesn't need
    server-side state -- the next request can re-derive the expected value
    from its own cookie. Rotating the cookie (new login) rotates the token;
    SameSite=Lax + this check together cover the same-site CSRF gap that
    SameSite alone leaves.
    """
    msg = b"csrf:" + session_cookie.encode("utf-8", "replace")
    return hmac.new(session_secret.encode(), msg, hashlib.sha256).hexdigest()


def check_csrf(session_secret: str, session_cookie: str, supplied: str | None) -> bool:
    """Const-time compare of a supplied CSRF token against the expected one."""
    if not supplied:
        return False
    expected = csrf_token(session_secret, session_cookie)
    a = expected.encode()
    b = supplied.encode()
    if len(a) != len(b):
        hmac.compare_digest(a, a)
        return False
    return hmac.compare_digest(a, b)


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
    resolve yet. The delivery-time check (resolve_safe_address) is what
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


def resolve_safe_address(
    url: str, *, allow_http: bool = False,
) -> tuple[str, int, str, str] | None:
    """DNS-pinned SSRF guard for outbound HTTP.

    Returns a tuple (resolved_ip, port, scheme, original_hostname) the caller
    should use to rewrite the request URL to the literal IP, while setting
    `Host: <original_hostname>` and TLS SNI to the same. This closes the
    TOCTOU window that `is_safe_for_delivery` leaves open: that function
    resolves DNS, then httpx re-resolves at connect time, so an attacker
    with a low-TTL authoritative server can return a public IP first and an
    internal IP second.

    Returns None when:
      - the URL fails the cheap shape check (`is_safe_url_shape`)
      - DNS resolution fails
      - every resolved address is private/loopback/link-local/multicast
    """
    if not is_safe_url_shape(url, allow_http=allow_http):
        log.warning("resolve_safe_address refused %s: unsafe_url_shape", url)
        return None
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host:
        log.warning("resolve_safe_address refused %s: unsafe_url_shape", url)
        return None
    port = parts.port or (443 if parts.scheme == "https" else 80)
    # Literal IPs short-circuit DNS but still get the private-range check.
    try:
        ipaddress.ip_address(host)
        if _ip_is_private(host):
            log.warning("resolve_safe_address refused %s: all_private", url)
            return None
        return host, port, parts.scheme, host
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        log.warning(
            "resolve_safe_address refused %s: dns_failed (%s: %s)",
            url, type(exc).__name__, exc,
        )
        return None
    for _fam, _t, _p, _c, sockaddr in infos:
        addr = sockaddr[0]
        if not _ip_is_private(addr):
            return addr, port, parts.scheme, host
    log.warning("resolve_safe_address refused %s: all_private", url)
    return None


def is_safe_for_delivery(url: str, *, allow_http: bool = False) -> tuple[bool, str | None]:
    """Legacy diagnostic helper — NOT called from the delivery path.

    Retained for boot-time URL validation (config self-check) and
    troubleshooting. `resolve_safe_address` is the authoritative outbound
    guard: it resolves once, refuses private addresses, and returns the
    literal IP so the caller can pin the connection.

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
