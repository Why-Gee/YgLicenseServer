"""License-issue email via Resend.

No-op when RESEND_API_KEY is unset — keeps tests + dev unaffected.
Best-effort: failures are logged but never raised, so a transient email
outage doesn't break license issuance.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from app.config import get_settings

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
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        _API,
        data=body,
        headers={
            "Authorization": f"Bearer {s.resend_api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if 200 <= resp.status < 300:
                log.info("email sent to %s for %s (resend status=%s)", to, product_name, resp.status)
                return True
            log.warning("resend returned %s for %s", resp.status, to)
            return False
    except urllib.error.HTTPError as e:
        log.warning("resend HTTPError %s for %s: %s", e.code, to, e.read()[:500])
        return False
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        log.warning("resend send failed for %s: %s", to, e)
        return False


def _format_from(addr: str, product_name: str) -> str:
    return f"{product_name} <{addr}>"


def _text_body(*, product_name: str, key: str) -> str:
    return (
        f"Thanks for licensing {product_name}.\n\n"
        f"Your license key:\n\n  {key}\n\n"
        "Set this as your LICENSE_KEY environment variable when installing the app.\n"
        "Keep it secret — anyone with this key can use the license.\n\n"
        "Reply to this email if you need help installing.\n"
    )
