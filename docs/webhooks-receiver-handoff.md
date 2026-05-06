# Webhook receiver — ASM hand-off

When LS pushes a license event (status change, delete) to your registered
webhook URL, the customer's app needs to verify the signature, then react
(invalidate cache, force phone-home, etc.).

This document covers two things to apply on the **AnimalShelterManager** side:

1. Make the phone-home interval configurable
2. Add a webhook receiver that the LS pushes to

Both are ASM-side changes — apply directly in the ASM repo.

---

## 1. Configurable phone-home interval

**File:** `backend/app/worker.py`

**Change** (find the `refresh_license` entry in `beat_schedule`):

```python
# OLD
"refresh-license": {
    "task": "app.licensing.tasks.refresh_license",
    "schedule": crontab(hour=3, minute=0),  # daily at 03:00
},
```

```python
# NEW
import os
_refresh_min = int(os.environ.get("LICENSE_REFRESH_MINUTES", "1440"))  # default 1 day
"refresh-license": {
    "task": "app.licensing.tasks.refresh_license",
    "schedule": crontab(minute=f"*/{_refresh_min}") if _refresh_min < 60 else crontab(minute=0, hour=f"*/{_refresh_min // 60}"),
},
```

(For raanana-kfar-saba's env, set `LICENSE_REFRESH_MINUTES=5`.)

---

## 2. Webhook receiver endpoint

**File:** new `backend/app/licensing/webhook_in.py`

```python
"""Inbound webhook from LicenseServer. Verifies HMAC signature, invalidates
cache, forces immediate phone-home.

Receiver protocol (matches LicenseServer/app/webhooks.py):
- Header X-License-Server-Signature: t=<unix-ts>,v1=<hmac-sha256-hex>
- HMAC over `<timestamp>.<raw-body>` with the per-license signing secret.
- Reject with 401 on bad signature or replay (>5min skew).
- Reject with 401 if LICENSE_WEBHOOK_SECRET unset.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time

from fastapi import APIRouter, Header, HTTPException, Request

from app.licensing.client import check_in
from app.licensing.client import _cache_path  # type: ignore[reportPrivateUsage]

log = logging.getLogger("aidb.licensing")
router = APIRouter()

REPLAY_WINDOW_SECONDS = 300  # 5 minutes


@router.post("/api/license/webhook")
async def license_webhook(
    request: Request,
    x_license_server_signature: str | None = Header(None),
) -> dict:
    secret = os.environ.get("LICENSE_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(status_code=401, detail="webhook receiver not configured")
    if not x_license_server_signature:
        raise HTTPException(status_code=401, detail="missing signature header")
    try:
        parts = dict(p.split("=", 1) for p in x_license_server_signature.split(","))
        ts = int(parts["t"])
        sig = parts["v1"]
    except (KeyError, ValueError) as e:
        raise HTTPException(status_code=401, detail="malformed signature") from e
    if abs(int(time.time()) - ts) > REPLAY_WINDOW_SECONDS:
        raise HTTPException(status_code=401, detail="signature too old")

    body = await request.body()
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise HTTPException(status_code=401, detail="bad signature")

    payload = json.loads(body)
    event_type = payload.get("type", "")
    log.info("license webhook received: %s id=%s", event_type, payload.get("id"))

    # Drop the cached JWT so the next request hits middleware -> reads fresh
    # state. Then force an immediate /v1/check so cache + upstream-status are
    # accurate within this request cycle (not after the next Celery beat).
    p = _cache_path()
    try:
        if p.exists():
            p.unlink()
    except OSError:
        pass
    try:
        check_in()
    except Exception as e:  # noqa: BLE001
        log.warning("post-webhook check_in failed: %s -- middleware will retry", e)

    return {"ok": True}
```

**Wire it up** in `backend/app/main.py` (or wherever routers are registered):

```python
from app.licensing.webhook_in import router as license_webhook_router
app.include_router(license_webhook_router)
```

**Allowlist the path** in `backend/app/licensing/middleware.py` so the webhook
receiver works even when the license is currently rejected (otherwise LS
can't tell the customer "you're back online" because the route is blocked):

```python
_ALLOWLIST_PREFIXES = (
    "/api/health",
    "/api/ready",
    "/api/public/",
    "/api/settings/public",
    "/api/auth/",
    "/api/me/features",
    "/api/license/webhook",   # <-- add this
)
```

---

## 3. Configure the receiver per tenant

**File:** `infra/.env.<tenant-slug>` (e.g. `.env.raanana-kfar-saba`)

Add:
```ini
LICENSE_WEBHOOK_SECRET=whsec_<paste-from-LS-after-issuance>
LICENSE_REFRESH_MINUTES=5
```

`LICENSE_WEBHOOK_SECRET` is whatever LS shows you on the issuance / update
screen. It is per-license and per-customer.

---

## 4. Register the URL with LS

After deploying ASM with the receiver:

- In LS admin UI, open the license row → expand the Webhook section.
- Paste the customer's URL: `https://<their-host>/api/license/webhook`
- Click Update — LS generates a new signing secret. Copy it into
  `LICENSE_WEBHOOK_SECRET` in the tenant's env file.
- Restart the tenant's backend.
- Click Test in the LS admin UI — should see HTTP 200 in the success banner.

---

## 5. Behavior after wiring

| Action in LS | Result on ASM |
|---|---|
| Disable license | Webhook fires → ASM clears cache + check_in → middleware sees `upstream_rejected={reason: disabled}` → next request 503s within ~1 second of the Disable click |
| Enable license | Webhook fires → ASM check_in succeeds → traffic resumes |
| Delete license | Webhook fires (`license.deleted`) → ASM clears cache → next check_in hits 401 invalid_key → 503 |
| LS unreachable | No webhook (LS is down). ASM polls every `LICENSE_REFRESH_MINUTES` and falls into the configured grace period. |

You also still want the **grace-bypass** middleware change (described in the
prior session) so that admin-initiated rejections don't get a 7-day grace.
With the webhook in place, that's a defense-in-depth: webhook is the fast
path; bypass-grace is what kicks in if the webhook ever fails to deliver.
