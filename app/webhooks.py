"""Outbound webhooks for license events.

Per-license `webhook_url` + `webhook_secret`. When the admin changes a
license's status (or deletes it), LS POSTs an HMAC-signed JSON body to
the URL. Receivers verify the signature and react however they want
(invalidate caches, force phone-home, etc.).

v1: synchronous best-effort delivery — failures logged, no retry queue.
Phase 2 can add a deliveries table + retry runner when volume justifies.

Inspired by Stripe's webhook design:
- X-License-Server-Signature: t=<unix-ts>,v1=<hmac-sha256-hex>
- HMAC over `<timestamp>.<raw-body>` to prevent replay
- Constant-time signature comparison on the receiver
- Each delivery has a unique X-License-Server-Event-Id for dedup

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
import urllib.error
import urllib.request
import uuid
from typing import Any

log = logging.getLogger("license-server.webhooks")

EVENT_STATUS_CHANGED = "license.status.changed"
EVENT_DELETED = "license.deleted"


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
) -> tuple[bool, int | None, str | None]:
    """POST a signed event to url. Returns (ok, http_status, error_msg).

    Best-effort: any exception (network, DNS, timeout) returns (False, None, err).
    Non-2xx HTTP returns (False, status, body_excerpt). Don't raise -- the caller
    is the request that triggered the status change, and we never want a webhook
    delivery to break license-issuance/disable/etc.
    """
    event_id = str(uuid.uuid4())
    timestamp = int(time.time())
    payload = {
        "id": event_id,
        "type": event_type,
        "created_at": timestamp,
        "data": data,
    }
    body = json.dumps(payload, separators=(",", ":")).encode()
    sig = sign(secret, timestamp, body)
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-License-Server-Event": event_type,
            "X-License-Server-Event-Id": event_id,
            "X-License-Server-Signature": f"t={timestamp},v1={sig}",
            "User-Agent": "YgLicenseServer-webhook/1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            if 200 <= status < 300:
                log.info("webhook delivered: %s %s -> %s", event_type, url, status)
                return True, status, None
            log.warning("webhook non-2xx: %s %s -> %s", event_type, url, status)
            return False, status, None
    except urllib.error.HTTPError as e:
        excerpt = e.read()[:200].decode("utf-8", "replace") if hasattr(e, "read") else ""
        log.warning("webhook HTTPError: %s %s -> %s (%s)", event_type, url, e.code, excerpt)
        return False, e.code, excerpt
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        log.warning("webhook send failed: %s %s: %s", event_type, url, e)
        return False, None, str(e)


def deliver_status_change(
    *, license_obj: Any, previous_status: str,
) -> tuple[bool, int | None, str | None] | None:
    """Convenience helper: derive payload from a License model + send. Returns
    None if no webhook configured on this license."""
    if not license_obj.webhook_url or not license_obj.webhook_secret:
        return None
    data = {
        "license_id": license_obj.id,
        "key": license_obj.key,
        "product_slug": license_obj.product.slug if license_obj.product else None,
        "customer_email": license_obj.customer.email if license_obj.customer else None,
        "previous_status": previous_status,
        "current_status": license_obj.status,
    }
    return deliver(
        url=license_obj.webhook_url, secret=license_obj.webhook_secret,
        event_type=EVENT_STATUS_CHANGED, data=data,
    )


def deliver_deleted(
    *, license_id: str, key: str, product_slug: str, customer_email: str,
    webhook_url: str, webhook_secret: str,
) -> tuple[bool, int | None, str | None]:
    """For deletions, the License row is gone by the time this fires, so the
    caller passes the snapshot fields directly."""
    data = {
        "license_id": license_id,
        "key": key,
        "product_slug": product_slug,
        "customer_email": customer_email,
    }
    return deliver(
        url=webhook_url, secret=webhook_secret,
        event_type=EVENT_DELETED, data=data,
    )
