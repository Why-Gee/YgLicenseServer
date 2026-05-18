"""License-issue email via Resend.

No-op when RESEND_API_KEY is unset — keeps tests + dev unaffected.
Best-effort: failures are logged but never raised, so a transient email
outage doesn't break license issuance.

Uses the shared httpx client (redirects disabled). Resend's API never
needs a redirect; if it ever does, we'd rather see the 301 in the log
than silently follow it.
"""
from __future__ import annotations

import logging
from email.utils import formataddr

import httpx

from app.config import get_settings
from app.http_client import get_client

log = logging.getLogger("license-server.email")

_API = "https://api.resend.com/emails"


def send_license_email(*, to: str, key: str, product_name: str) -> bool:
    """Returns True if the email was dispatched, False otherwise (incl. unconfigured)."""
    s = get_settings()
    if not s.resend_api_key:
        log.info("email skipped (RESEND_API_KEY unset): would send key for %s to %s", product_name, to)
        return False

    payload = {
        "from": _format_from(s.email_from, product_name),
        "to": [to],
        "subject": f"Your {product_name} license key",
        "text": _text_body(product_name=product_name, key=key),
    }
    try:
        r = get_client().post(
            _API,
            json=payload,
            headers={
                "Authorization": f"Bearer {s.resend_api_key}",
                "Content-Type": "application/json",
            },
            timeout=10.0,
        )
    except httpx.HTTPError as e:
        log.warning("resend send failed for %s: %s", to, e)
        return False

    if 200 <= r.status_code < 300:
        log.info("email sent to %s for %s (resend status=%s)", to, product_name, r.status_code)
        return True
    log.warning("resend returned %s for %s: %s", r.status_code, to, r.text[:500])
    return False


def _format_from(addr: str, product_name: str) -> str:
    """RFC-5322 formatted From with the product name as the display name.
    Uses email.utils.formataddr so unusual characters in product_name don't
    blow up the header."""
    return formataddr((product_name, addr))


def _text_body(*, product_name: str, key: str) -> str:
    return (
        f"Thanks for licensing {product_name}.\n\n"
        f"Your license key:\n\n  {key}\n\n"
        "Set this as your LICENSE_KEY environment variable when installing the app.\n"
        "Keep it secret — anyone with this key can use the license.\n\n"
        "Reply to this email if you need help installing.\n"
    )


def send_expiry_warning_email(
    *, to: str, key: str, product_name: str, days_left: int, valid_until_iso: str,
) -> bool:
    """Pre-expiry warning. Sent N days before valid_until lapses so the
    customer can renew before downtime. Returns True iff dispatched."""
    s = get_settings()
    if not s.resend_api_key:
        log.info(
            "expiry email skipped (RESEND_API_KEY unset): would warn %s about %s (%d days)",
            to, product_name, days_left,
        )
        return False

    subject = f"Your {product_name} license expires in {days_left} day{'s' if days_left != 1 else ''}"
    text = (
        f"Your {product_name} license expires on {valid_until_iso}.\n\n"
        f"License key (for reference, do not share):\n  {key}\n\n"
        f"That's {days_left} day{'s' if days_left != 1 else ''} from today. "
        "Reply to this email to renew or extend.\n"
    )
    payload = {
        "from": _format_from(s.email_from, product_name),
        "to": [to],
        "subject": subject,
        "text": text,
    }
    try:
        r = get_client().post(
            _API,
            json=payload,
            headers={
                "Authorization": f"Bearer {s.resend_api_key}",
                "Content-Type": "application/json",
            },
            timeout=10.0,
        )
    except httpx.HTTPError as e:
        log.warning("resend expiry warning failed for %s: %s", to, e)
        return False
    if 200 <= r.status_code < 300:
        log.info("expiry warning sent to %s (%d days, product=%s)", to, days_left, product_name)
        return True
    log.warning("resend returned %s for %s: %s", r.status_code, to, r.text[:500])
    return False
