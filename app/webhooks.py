"""Outbound webhooks for license events.

Per-license `webhook_url` + `webhook_secret`. When the admin changes a
license's status (or deletes it), LS POSTs an HMAC-signed JSON body to
the URL. Receivers verify the signature and react however they want
(invalidate caches, force phone-home, etc.).

v2 (v0.12): durable retry queue. Each delivery is persisted to
`webhook_deliveries` inside the SAME DB transaction as the state change,
so a server crash between commit and the first send leaves the row in
status='pending' for the retry worker to pick up. Backoff schedule:
1min, 5min, 30min, 2h, 12h, 24h -> abandon after 7 attempts.

Inspired by Stripe's webhook design:
- X-License-Server-Signature: t=<unix-ts>,v1=<hmac-sha256-hex>
- HMAC over `<timestamp>.<raw-body>` to prevent replay
- Constant-time signature comparison on the receiver
- Each delivery has a unique X-License-Server-Event-Id for dedup

Transport notes:
- Uses the shared httpx.Client from app.http_client. Redirects are
  disabled there, so a hostile receiver can't 302 us to an internal IP.
- Before each call we run app.security.resolve_safe_address(). It
  resolves the hostname once, returns the literal IP, and deliver()
  rewrites the request URL to that IP so httpx never re-resolves at
  connect time (closes the DNS-rebinding TOCTOU). The original hostname
  rides in the Host header and TLS SNI so virtual-hosting and cert
  validation against the hostname still work.

Receiver pseudo-code (any language):

    secret = os.environ["LICENSE_WEBHOOK_SECRET"]
    sig = request.headers["X-License-Server-Signature"]
    parts = dict(p.split("=", 1) for p in sig.split(","))
    body = request.get_data(as_text=True)
    expected = hmac_sha256_hex(secret, f"{parts['t']}.{body}")
    if not hmac.compare_digest(expected, parts["v1"]):
        return 401
    if abs(now() - int(parts["t"])) > 300:  # 5 min replay window
        return 401
    payload = json.loads(body)
    # ... act on payload["type"] ...
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx

from app._time import utcnow
from app.http_client import get_client
from app.security import is_safe_url_shape, resolve_safe_address

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from app.models import WebhookDelivery

log = logging.getLogger("license-server.webhooks")

EVENT_STATUS_CHANGED = "license.status.changed"
EVENT_DELETED = "license.deleted"
EVENT_UPDATED = "license.updated"

# Backoff schedule for retries. Applied AFTER each failure -- the i-th
# failed attempt schedules the (i+1)-th attempt at now + SCHEDULE[i-1].
# After MAX_ATTEMPTS failures we give up and mark the delivery 'abandoned';
# operator can re-trigger manually if they want another shot.
BACKOFF_SCHEDULE = (
    timedelta(minutes=1),
    timedelta(minutes=5),
    timedelta(minutes=30),
    timedelta(hours=2),
    timedelta(hours=12),
    timedelta(hours=24),
)
MAX_ATTEMPTS = len(BACKOFF_SCHEDULE) + 1  # 7 total: initial + 6 retries


def generate_secret() -> str:
    """Webhook signing secret. Caller stores it on the License row + shows
    it once to the admin so they can configure the receiver."""
    return f"whsec_{secrets.token_urlsafe(32)}"


def sign(secret: str, timestamp: int, body: bytes) -> str:
    """Stripe-style HMAC-SHA256. Returns just the hex digest -- caller
    formats the full `t=...,v1=...` header."""
    msg = f"{timestamp}.".encode() + body
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def deliver(
    *, url: str, secret: str, event_type: str, data: dict[str, Any],
    timeout: float = 5.0,
    event_id: str | None = None,
    timestamp: int | None = None,
    allow_http: bool = False,
) -> tuple[bool, int | None, str | None]:
    """POST a signed event to url. Returns (ok, http_status, error_msg).

    Best-effort: any network exception returns (False, None, err); non-2xx
    HTTP returns (False, status, body_excerpt). Don't raise -- the caller
    is the request that triggered the status change, and we never want a
    webhook delivery to break license-issuance/disable/etc.

    SSRF guard: resolve_safe_address() resolves the URL once and rewrites
    the connection to the literal IP, pinning DNS and closing the TOCTOU
    window. Refusal cases (all return False, consume one retry attempt, and
    schedule the next via the backoff worker — same treatment as a 5xx):
      - URL fails the cheap shape check (bad scheme, literal private IP, *.local, ...)
      - DNS resolution fails (OSError from getaddrinfo)
      - Every resolved address is private/loopback/link-local/multicast

    `event_id` + `timestamp` are passed through when retrying a previously-
    enqueued delivery so the receiver-side dedup-by-event-id keeps working
    across retries.

    `allow_http` controls the URL-shape check at the per-call boundary.
    Defaults to False (HTTPS-only) to match the safer per-license default;
    callers with a license that has allow_http_webhook=True pass True.
    """
    ok_url = is_safe_url_shape(url, allow_http=allow_http)
    if not ok_url:
        log.warning("webhook refused (unsafe url shape): %s", url)
        return False, None, "refused:unsafe_url_shape"
    resolved = resolve_safe_address(url, allow_http=allow_http)
    if resolved is None:
        # resolve_safe_address already logged the specific reason (shape /
        # dns_failed / all_private) at WARNING level.
        log.warning("webhook refused (see above): %s", url)
        return False, None, "refused:unsafe_url"
    ip, port, scheme, host = resolved

    if event_id is None:
        event_id = str(uuid.uuid4())
    if timestamp is None:
        timestamp = int(time.time())
    payload = {
        "id": event_id,
        "type": event_type,
        "created_at": timestamp,
        "data": data,
    }
    body = json.dumps(payload, separators=(",", ":")).encode()
    sig = sign(secret, timestamp, body)
    headers = {
        "Content-Type": "application/json",
        "X-License-Server-Event": event_type,
        "X-License-Server-Event-Id": event_id,
        "X-License-Server-Signature": f"t={timestamp},v1={sig}",
    }
    # Rewrite URL host → literal IP so httpx's own resolver can't change
    # answers between our check and connect. Preserve the original hostname
    # in the Host header + TLS SNI so virtual-hosting and certs still work.
    ip_for_url = f"[{ip}]" if ":" in ip else ip
    parts = urlsplit(url)
    pinned_url = f"{scheme}://{ip_for_url}:{port}{parts.path or '/'}"
    if parts.query:
        pinned_url += "?" + parts.query
    pinned_headers = {**headers, "Host": host}
    try:
        r = get_client().post(
            pinned_url,
            content=body,
            headers=pinned_headers,
            timeout=timeout,
            extensions={"sni_hostname": host},
        )
    except httpx.HTTPError as e:
        log.warning("webhook send failed: %s %s: %s", event_type, url, e)
        return False, None, str(e)

    status = r.status_code
    if 200 <= status < 300:
        log.info("webhook delivered: %s %s -> %s", event_type, url, status)
        return True, status, None
    excerpt = r.text[:200] if r.text else ""
    log.warning("webhook non-2xx: %s %s -> %s (%s)", event_type, url, status, excerpt)
    return False, status, excerpt


def deliver_status_change(
    *, license_obj: Any, previous_status: str,
) -> tuple[bool, int | None, str | None] | None:
    """Convenience helper: derive payload from a License model + send. Returns
    None if no webhook configured on this license."""
    if not license_obj.webhook_url or not license_obj.webhook_secret:
        return None
    data = {
        "license_id": license_obj.id,
        "license_key": license_obj.key,
        "key": license_obj.key,
        "product_slug": license_obj.product.slug if license_obj.product else None,
        "customer_email": license_obj.customer.email if license_obj.customer else None,
        "previous_status": previous_status,
        "current_status": license_obj.status,
    }
    return deliver(
        url=license_obj.webhook_url, secret=license_obj.webhook_secret,
        event_type=EVENT_STATUS_CHANGED, data=data,
        allow_http=bool(license_obj.allow_http_webhook),
    )


def deliver_update(
    *, license_obj: Any, changed_fields: list[str],
) -> tuple[bool, int | None, str | None] | None:
    """Fire when admin edits a license without changing its status — features,
    plan, max_users, valid_until, etc. Receivers invalidate their cached JWT
    so the next call surfaces the new values. Returns None when no webhook is
    configured for this license."""
    if not license_obj.webhook_url or not license_obj.webhook_secret:
        return None
    data = {
        "license_id": license_obj.id,
        "license_key": license_obj.key,
        "key": license_obj.key,
        "product_slug": license_obj.product.slug if license_obj.product else None,
        "customer_email": license_obj.customer.email if license_obj.customer else None,
        "status": license_obj.status,
        "changed_fields": changed_fields,
    }
    return deliver(
        url=license_obj.webhook_url, secret=license_obj.webhook_secret,
        event_type=EVENT_UPDATED, data=data,
        allow_http=bool(license_obj.allow_http_webhook),
    )


def deliver_deleted(
    *, license_id: str, key: str, product_slug: str, customer_email: str,
    webhook_url: str, webhook_secret: str,
) -> tuple[bool, int | None, str | None]:
    """For deletions, the License row is gone by the time this fires, so the
    caller passes the snapshot fields directly. The allow_http flag is inferred
    from the stored URL's scheme — the URL was validated at configure time so
    if it starts with http:// the flag must have been True then."""
    data = {
        "license_id": license_id,
        "license_key": key,
        "key": key,
        "product_slug": product_slug,
        "customer_email": customer_email,
    }
    return deliver(
        url=webhook_url, secret=webhook_secret,
        event_type=EVENT_DELETED, data=data,
        allow_http=webhook_url.startswith("http://"),
    )


# ----- retry-queue plumbing ---------------------------------------------

def enqueue(
    db: Session, *,
    url: str, secret: str, event_type: str, data: dict[str, Any],
    license_id: str | None = None, product_id: str | None = None,
) -> WebhookDelivery:
    """Persist a pending delivery row. Call BEFORE the caller's db.commit()
    so the queue insert is atomic with the state change that triggered the
    webhook -- a rollback drops both, a commit makes both durable.

    The payload is serialized to JSON now and stored verbatim; retries
    sign the same bytes so receiver-side timestamp validation is the only
    thing that needs to budge between attempts."""
    from app.models import WebhookDelivery
    d = WebhookDelivery(
        url=url, secret=secret, event_type=event_type,
        payload_json=json.dumps(data, separators=(",", ":")),
        license_id=license_id, product_id=product_id,
        status="pending",
        next_attempt_at=utcnow(),
    )
    db.add(d)
    db.flush()  # populate d.id without committing
    return d


def try_deliver(db: Session, delivery_id: str) -> bool:
    """Attempt one HTTP send for a pending delivery. Updates the row in
    place: on success status='delivered'; on failure either bumps attempts
    + schedules the next try, or status='abandoned' if the schedule is
    exhausted. Caller owns the commit.

    Returns True iff the row transitioned to 'delivered'."""
    from app.models import License, WebhookDelivery
    d = db.query(WebhookDelivery).filter_by(id=delivery_id).one_or_none()
    if d is None or d.status != "pending":
        return False
    try:
        data = json.loads(d.payload_json)
    except json.JSONDecodeError as e:
        d.status = "abandoned"
        d.last_error = f"payload_decode: {e}"
        return False
    # Read the live license's flag if the license still exists, otherwise
    # infer from the stored URL scheme (the URL was already validated at
    # enqueue time, so its scheme is a reliable proxy for the deleted
    # license's flag). An admin flipping allow_http_webhook OFF on a live
    # license MUST be respected for in-flight retries — that's why the
    # fallback is conditioned on license absence, not on flag value.
    allow_http = False
    if d.license_id:
        lic = db.query(License).filter_by(id=d.license_id).one_or_none()
        if lic is not None:
            allow_http = bool(lic.allow_http_webhook)
        else:
            allow_http = d.url.startswith("http://")
    else:
        allow_http = d.url.startswith("http://")
    # Resign fresh on each attempt so receiver-side replay windows (5min
    # default) don't reject a backed-off retry. Receiver dedups on the
    # X-License-Server-Event-Id header which we DON'T regenerate -- so
    # idempotent receivers see one logical event regardless of retries.
    ok, status, err = deliver(
        url=d.url, secret=d.secret, event_type=d.event_type, data=data,
        event_id=d.id,
        allow_http=allow_http,
    )
    d.attempts += 1
    d.last_attempt_at = utcnow()
    # Record what the receiver returned (observability). response_status is the
    # HTTP code, or NULL when we never reached the receiver (network / TLS /
    # timeout / SSRF-refusal). On a non-2xx, deliver() returns the body excerpt
    # as `err` -> response_excerpt; network/refusal failures have no body (their
    # detail lives in last_error), so excerpt stays NULL there.
    d.response_status = status
    d.response_excerpt = ((err or "")[:500] or None) if status is not None else None
    if ok:
        d.status = "delivered"
        d.delivered_at = utcnow()
        d.last_error = None
        return True
    d.last_error = (err or "(no detail)")[:500]
    if d.attempts >= MAX_ATTEMPTS:
        d.status = "abandoned"
        log.warning(
            "webhook delivery %s abandoned after %d attempts: %s",
            d.id, d.attempts, d.last_error,
        )
        return False
    backoff = BACKOFF_SCHEDULE[d.attempts - 1]
    d.next_attempt_at = utcnow() + backoff
    log.info(
        "webhook delivery %s will retry in %s (attempt %d/%d)",
        d.id, backoff, d.attempts, MAX_ATTEMPTS,
    )
    return False


def attempt_in_fresh_session(delivery_id: str) -> bool:
    """Wrapper for the post-commit hook: opens a fresh SessionLocal, calls
    try_deliver, commits. Used by the service-layer `_run(...)` lambdas
    that fire after the triggering transaction has already closed.

    Returns True iff delivered on this attempt."""
    from app.db import SessionLocal
    s = SessionLocal()
    try:
        ok = try_deliver(s, delivery_id)
        s.commit()
        return ok
    except Exception:
        s.rollback()
        log.exception("post-commit webhook attempt failed")
        return False
    finally:
        s.close()
