# Phase 3 — Network + Deploy Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Default webhook delivery to HTTPS (per-license `allow_http` opt-in for LAN installs), harden the Caddyfile with `trusted_proxies` + security headers; ship as v0.23.0.

**Architecture:** Two small surface changes. (1) `is_safe_url_shape` defaults `allow_http=False` and gains a new per-license override stored on the `License` model; existing callers thread the override through. (2) Caddyfile gains a `trusted_proxies` block plus a `header` directive setting HSTS, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy on every response. Pyproject version drift was already healed in Phase 1's v0.21.0 bump — no further action required.

**Tech Stack:** No new deps. SQLAlchemy 2.0, Alembic, Caddy v2.

**Spec:** `docs/superpowers/specs/2026-05-22-security-hardening-design.md` (Phase 3 section).

**Branch:** `yg/Vulnerabilities-21-5-2026` (continued from Phase 2).

---

## File Structure

**Modified:**
- `app/models.py` — new `License.allow_http_webhook` boolean column.
- `app/security.py::is_safe_url_shape` — default `allow_http=False` (was the function-level default; callers that need http opt in explicitly).
- `app/services/check.py::check_license` — pass `allow_http=lic.allow_http_webhook` when validating self-registered `public_url`.
- `app/services/licenses.py::apply_webhook_config`, `issue_license` — accept `allow_http: bool = False` kwarg; thread into `is_safe_url_shape`; set `lic.allow_http_webhook` accordingly.
- `app/routers/admin_ui/licenses.py` — `license_issue`, `license_edit`, `license_webhook_update` accept the new form field `allow_http_webhook` and pass through.
- `app/templates/product_detail.html` — checkbox in the license modal under the webhook URL field.
- `app/static/admin.js` — read/write the checkbox in the license-modal open/save logic.
- `app/webhooks.py::deliver` — when calling `resolve_safe_address`, pass `allow_http=` from the license context. NOTE: `deliver()` today receives the URL but not the license, so we need to plumb the flag through the call chain or compute it from the URL shape.

**Created:**
- `alembic/versions/<rev>_allow_http_webhook.py` — adds column + backfills `TRUE` for existing rows whose `webhook_url` starts with `http://`.

**Deploy:**
- `deploy/gcp/Caddyfile` — `trusted_proxies` + security headers.

**Tests:**
- `tests/test_phase3_deploy.py` — TDD tests for H5 (HTTPS-only default, http opt-in path, migration backfill).

---

## Task 1: H5 — HTTPS-only webhooks with `allow_http` opt-in

**Files:**
- Modify: `app/security.py::is_safe_url_shape` — flip default to `allow_http=False`.
- Modify: `app/models.py` — add `License.allow_http_webhook` column.
- Create: `alembic/versions/<rev>_allow_http_webhook.py`.
- Modify: `app/services/check.py`, `app/services/licenses.py`.
- Modify: `app/routers/admin_ui/licenses.py`.
- Modify: `app/templates/product_detail.html`, `app/static/admin.js`.
- Modify: `app/webhooks.py::deliver` (read flag from URL context).
- Test: `tests/test_phase3_deploy.py` (new file).

The default in `is_safe_url_shape` today is `allow_http=True` for callers that opt in (webhook code passes `True`). We flip to `allow_http=False` so the safe path is HTTPS, and add a per-license `allow_http_webhook` boolean for the explicit "this is a LAN install on a customer site, http is fine" case.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_phase3_deploy.py`:

```python
"""Phase 3 network/deploy hardening — TDD tests for H5."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _admin_login(client: TestClient) -> dict[str, str]:
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return {"ls_session": r.cookies["ls_session"]}


def _csrf_for(cookies: dict[str, str]) -> str:
    from app.config import get_settings
    from app.security import csrf_token
    return csrf_token(get_settings().session_secret, cookies["ls_session"])


def _form_post(client: TestClient, url: str, cookies: dict[str, str], data: dict | None = None, **kw):
    payload = dict(data or {})
    payload.setdefault("csrf_token", _csrf_for(cookies))
    return client.post(url, data=payload, cookies=cookies, **kw)


def _create_product(client: TestClient, slug: str = "asm") -> None:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": slug, "name": slug.upper(), "key_prefix": slug},
    )
    assert r.status_code == 200, r.text


# ---------- H5: HTTPS-only webhook default ---------------------------------


def test_issue_with_http_webhook_rejected_by_default(client):
    """Issuing a license with an http:// webhook URL must fail when
    allow_http_webhook is not set (the new safe default)."""
    _create_product(client)
    cookies = _admin_login(client)
    r = _form_post(
        client, "/admin/products/asm/licenses", cookies,
        data={
            "email": "alice@example.com", "plan": "standard",
            "max_users": "10", "valid_days": "30", "features_json": "{}",
            "webhook_url": "http://customer.lan/wh",
            # no allow_http_webhook field
        },
        follow_redirects=False,
    )
    # Form handler returns a 303 to ?error=... on Unsafe
    assert r.status_code == 303, r.text
    assert "error=unsafe" in r.headers["location"], r.headers["location"]


def test_issue_with_http_webhook_accepted_when_allow_http_set(client):
    """Same call WITH allow_http_webhook=1 succeeds; license row is
    persisted with allow_http_webhook=True."""
    _create_product(client)
    cookies = _admin_login(client)
    r = _form_post(
        client, "/admin/products/asm/licenses", cookies,
        data={
            "email": "alice@example.com", "plan": "standard",
            "max_users": "10", "valid_days": "30", "features_json": "{}",
            "webhook_url": "http://customer.lan/wh",
            "allow_http_webhook": "1",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "issued=" in r.headers["location"], r.headers["location"]
    # Row in DB has the flag set.
    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        lic = s.query(License).first()
        assert lic is not None
        assert lic.allow_http_webhook is True
        assert lic.webhook_url == "http://customer.lan/wh"


def test_issue_with_https_webhook_does_not_set_allow_http_flag(client):
    """An https URL issue path leaves allow_http_webhook=False (the column
    default). HTTPS URLs never need the flag."""
    _create_product(client)
    cookies = _admin_login(client)
    r = _form_post(
        client, "/admin/products/asm/licenses", cookies,
        data={
            "email": "alice@example.com", "plan": "standard",
            "max_users": "10", "valid_days": "30", "features_json": "{}",
            "webhook_url": "https://customer.example.com/wh",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "issued=" in r.headers["location"]
    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        lic = s.query(License).first()
        assert lic.allow_http_webhook is False
        assert lic.webhook_url.startswith("https://")


def test_v1_check_public_url_http_rejected_unless_allow_http_set(client):
    """A client self-registering an http:// public_url via /v1/check is
    rejected by default; opting in (admin sets allow_http_webhook=True on
    the row) makes it succeed. This test asserts the default-reject."""
    _create_product(client)
    cookies = _admin_login(client)
    # Issue a license with NO webhook (source='self', allow_http_webhook=False).
    r = _form_post(
        client, "/admin/products/asm/licenses", cookies,
        data={
            "email": "alice@example.com", "plan": "standard",
            "max_users": "10", "valid_days": "30", "features_json": "{}",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    r = client.get(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
    )
    key = r.json()["items"][0]["key"]
    # Client tries to self-register an http URL.
    r = client.post(
        "/v1/check",
        json={
            "key": key, "install_id": "ii-1", "version": "1.0",
            "public_url": "http://customer.lan/wh",
        },
    )
    assert r.status_code == 400, r.text
    assert r.json().get("detail", {}).get("reason") == "invalid_public_url"
```

- [ ] **Step 2: Run — verify failure**

```bash
pytest tests/test_phase3_deploy.py -v
```

Expected: all four tests FAIL (no allow_http_webhook column; current default `allow_http=True` accepts http).

- [ ] **Step 3: Flip the `is_safe_url_shape` default**

Edit `app/security.py`. The function signature today is:

```python
def is_safe_url_shape(url: str, *, allow_http: bool = False) -> bool:
```

— actually it ALREADY defaults to `False`. The behaviour change is at the call sites. **Confirm by reading `app/security.py`** that the default is indeed `False`; no change needed in `security.py` if so.

The change is that webhook callers must STOP passing `allow_http=True` unconditionally. They will pass `allow_http=lic.allow_http_webhook` (or the form field value during issue/edit).

- [ ] **Step 4: Add `allow_http_webhook` to `app/models.py::License`**

Append after `webhook_url_source`:

```python
    # Per-license http:// opt-in. When True, webhook URLs may use the http
    # scheme (intended for customer-LAN installs). Default False; HTTPS-only
    # is the safe default. Migration backfills True for existing rows whose
    # webhook_url already starts with http:// so behaviour doesn't regress.
    allow_http_webhook: Mapped[bool] = mapped_column(
        Integer, default=0, nullable=False,
    )
```

(Stored as `Integer` to match the existing `enabled` column on `AdminMfa`; SQLAlchemy returns int 0/1.)

- [ ] **Step 5: Write the Alembic migration**

```bash
alembic revision -m "allow_http_webhook"
```

Edit the generated file:

```python
"""allow_http_webhook column

Revision ID: <keep generated>
Revises: 570f101254e2
Create Date: <keep generated>

Adds licenses.allow_http_webhook (bool, default False). Backfills True
for any existing row whose webhook_url starts with http:// so a deploy
that already had http webhooks configured keeps working post-upgrade.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "<keep generated>"
down_revision: str | Sequence[str] | None = "570f101254e2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("licenses") as batch:
        batch.add_column(
            sa.Column(
                "allow_http_webhook",
                sa.Integer,
                nullable=False,
                server_default=sa.text("0"),
            )
        )
    # Backfill: existing http:// URLs were configured deliberately; preserve.
    op.execute(
        "UPDATE licenses SET allow_http_webhook = 1 "
        "WHERE webhook_url LIKE 'http://%'"
    )


def downgrade() -> None:
    with op.batch_alter_table("licenses") as batch:
        batch.drop_column("allow_http_webhook")
```

- [ ] **Step 6: Thread `allow_http` through `app/services/licenses.py`**

`apply_webhook_config` and `issue_license` need the flag.

For `apply_webhook_config`, change signature + body to read `allow_http` from the License row:

```python
def apply_webhook_config(
    lic: License, *, url: str | None, rotate: bool, mint_on_url_change: bool,
    source: str = "admin",
    allow_http: bool | None = None,
) -> None:
    """... existing docstring ...

    `allow_http` (when not None) overrides `lic.allow_http_webhook` for the
    validation check; None means use whatever is already on the row. Caller
    passes True to flip the row's flag to True alongside setting an http URL;
    None preserves the existing flag value.
    """
    if url:
        effective_allow_http = (
            allow_http if allow_http is not None else bool(lic.allow_http_webhook)
        )
        if not is_safe_url_shape(url, allow_http=effective_allow_http):
            raise Unsafe("unsafe webhook url")
        should_mint = (
            rotate
            or not lic.webhook_secret
            or (mint_on_url_change and lic.webhook_url != url)
        )
        if should_mint:
            lic.webhook_secret = wh.generate_secret()
        lic.webhook_url = url
        lic.webhook_url_source = source
        if allow_http is not None:
            lic.allow_http_webhook = 1 if allow_http else 0
    else:
        lic.webhook_url = None
        lic.webhook_secret = None
        lic.webhook_url_source = "self"
        lic.allow_http_webhook = 0
```

For `issue_license`, change the signature to accept `allow_http_webhook: bool = False` and pass through:

```python
def issue_license(
    db: Session,
    *,
    product: Product,
    email: str,
    name: str | None = None,
    plan: str = "standard",
    max_users: int = 10,
    valid_days: int = 365,
    features: dict | None = None,
    webhook_url: str | None = None,
    allow_http_webhook: bool = False,
    stripe_customer_id: str | None = None,
    note: str = "service/issue",
    send_email: bool = False,
) -> IssueResult:
    """... existing docstring ..."""
    name_clean = (name or "").strip() or None
    # ... existing customer-resolution code stays ...

    webhook_url_clean = (webhook_url or "").strip() or None
    if webhook_url_clean and not is_safe_url_shape(
        webhook_url_clean, allow_http=allow_http_webhook,
    ):
        raise Unsafe("unsafe webhook url")
    webhook_secret_value = wh.generate_secret() if webhook_url_clean else None
    webhook_source_value = "admin" if webhook_url_clean else "self"

    key = f"{product.key_prefix}_" + secrets.token_urlsafe(32)
    lic = License(
        product_id=product.id,
        customer_id=cust.id,
        key=key,
        plan=plan,
        max_users=max_users,
        features=features or {},
        valid_until=_utcnow() + timedelta(days=valid_days),
        status="active",
        webhook_url=webhook_url_clean,
        webhook_secret=webhook_secret_value,
        webhook_url_source=webhook_source_value,
        allow_http_webhook=1 if allow_http_webhook else 0,
    )
    db.add(lic)
    # ... rest of function stays ...
```

Update `configure_webhook` to surface the same kwarg:

```python
def configure_webhook(
    db: Session, lic: License, *,
    url: str | None,
    rotate: bool,
    mint_on_url_change: bool = True,
    source: str = "admin",
    allow_http: bool | None = None,
    note: str = "service/webhook",
    payload_extra: dict | None = None,
) -> None:
    apply_webhook_config(
        lic, url=url, rotate=rotate, mint_on_url_change=mint_on_url_change,
        source=source, allow_http=allow_http,
    )
    payload = {"set": bool(url)}
    if payload_extra:
        payload.update(payload_extra)
    db.add(Event(
        license_id=lic.id, product_id=lic.product_id, type="webhook:updated",
        payload=payload, note=note,
    ))
    db.commit()
```

- [ ] **Step 7: Thread `allow_http` through `app/services/check.py`**

When validating self-registered `public_url`, use the license's stored flag:

```python
    if public_url is not None and public_url.strip():
        candidate = public_url.strip().rstrip("/")
        if len(candidate) > 500 or not is_safe_url_shape(
            candidate, allow_http=bool(lic.allow_http_webhook),
        ):
            raise CheckRejected("invalid_public_url", http_status=400)
        ...
```

(Just changes the `allow_http=True` literal to `allow_http=bool(lic.allow_http_webhook)`.)

- [ ] **Step 8: Add the form field in `app/routers/admin_ui/licenses.py`**

In `license_issue`:

```python
@router.post("/admin/products/{slug}/licenses")
def license_issue(
    slug: str,
    request: Request,
    email: str = Form(...),
    customer_name: str = Form(""),
    plan: str = Form("standard"),
    max_users: int = Form(10),
    valid_days: int = Form(365),
    features_json: str = Form("{}"),
    webhook_url: str = Form(""),
    allow_http_webhook: str = Form(""),   # NEW
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    # ... existing product + features parsing ...
    try:
        result = licenses_svc.issue_license(
            db, product=p, email=email, name=customer_name,
            plan=plan, max_users=max_users, valid_days=valid_days,
            features=features,
            webhook_url=webhook_url or None,
            allow_http_webhook=(allow_http_webhook == "1"),   # NEW
            note="ui/issue",
        )
    except Unsafe as e:
        return RedirectResponse(
            f"/admin/products/{slug}?error={err_code(e)}", status_code=303
        )
    return RedirectResponse(
        f"/admin/products/{slug}?issued={result.license.id}", status_code=303
    )
```

In `license_webhook_update`:

```python
@router.post("/admin/licenses/{lid}/webhook")
def license_webhook_update(
    lid: str,
    request: Request,
    webhook_url: str = Form(""),
    allow_http_webhook: str = Form(""),    # NEW
    rotate_secret: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    new_url = webhook_url.strip() or None
    try:
        licenses_svc.configure_webhook(
            db, lic, url=new_url, rotate=rotate_secret == "1",
            mint_on_url_change=True,
            allow_http=(allow_http_webhook == "1"),   # NEW
            note="ui/webhook",
        )
    except Unsafe as e:
        return RedirectResponse(
            f"/admin/products/{lic.product.slug}?error={err_code(e)}",
            status_code=303,
        )
    return RedirectResponse(
        f"/admin/products/{lic.product.slug}?webhook_lid={lic.id}", status_code=303
    )
```

(Add a comparable field to `license_edit` — it accepts `webhook_url` already, so add `allow_http_webhook` next to it and pass to `edit_license`.)

For `edit_license` in `app/services/licenses.py`, add the kwarg + plumb to `apply_webhook_config`:

```python
def edit_license(
    db: Session, lic: License, *,
    plan: str,
    max_users: int,
    valid_until_raw: str,
    features_json: str = "{}",
    webhook_url: str = "",
    allow_http_webhook: bool | None = None,
    rotate_secret: bool = False,
    note: str = "service/edit",
    schedule: Scheduler | None = None,
) -> EditResult:
    # ... existing parsing of features + valid_until ...
    # ... existing change-tracking code ...

    new_url = webhook_url.strip() or None
    prev_secret = lic.webhook_secret
    apply_webhook_config(
        lic, url=new_url, rotate=rotate_secret, mint_on_url_change=True,
        allow_http=allow_http_webhook,
    )
    # ... rest stays ...
```

And in the licenses.py router's `license_edit`:

```python
    allow_http_webhook: str = Form(""),
    ...
    result = licenses_svc.edit_license(
        db, lic,
        plan=plan, max_users=max_users, valid_until_raw=valid_until,
        features_json=features_json,
        webhook_url=webhook_url,
        allow_http_webhook=(allow_http_webhook == "1") if allow_http_webhook else None,
        rotate_secret=rotate_secret == "1",
        note="ui/edit",
        schedule=bg.add_task,
    )
```

(`None` when the field isn't submitted preserves existing behaviour.)

- [ ] **Step 9: Add the checkbox in `app/templates/product_detail.html`**

Find the webhook URL block in the license modal (search for `lm-webhook-url`). Below the URL input + Update/Test buttons block, before the `lm-rotate-row`, add:

```html
      <div id="lm-allow-http-row" style="grid-column:1/-1;display:none;">
        <label style="display:inline-flex;align-items:center;gap:.4em;font-weight:normal;">
          <input id="lm-allow-http" name="allow_http_webhook" type="checkbox" value="1"
                 style="width:auto;margin:0;">
          Allow plain http:// (LAN install only)
        </label>
        <small class="muted" style="display:block;margin-top:.2em;">
          HTTPS is required by default. Tick only for customer-LAN installs
          that can't get a TLS cert — webhook bodies will travel in cleartext.
        </small>
      </div>
```

In the JS block (still in `product_detail.html`), pre-fill the checkbox from license data and tie its visibility to having a webhook URL in scope:

```javascript
  var allowHttpRow = document.getElementById('lm-allow-http-row');
  var allowHttpCb = document.getElementById('lm-allow-http');
```

In the `open(mode, lic)` function's edit branch, add:

```javascript
      allowHttpRow.style.display = '';
      allowHttpCb.checked = !!lic.allow_http_webhook;
```

In the create branch:

```javascript
      allowHttpRow.style.display = '';
      allowHttpCb.checked = false;
```

In the per-license JSON payload at the top of the file (search for `webhook_secret`), add:

```javascript
      "allow_http_webhook": {{ 1 if lic.allow_http_webhook else 0 }},
```

And in the `snapshot:` block of the dirty-guard helper, add the field:

```javascript
        allow_http_webhook: allowHttpCb.checked,
```

- [ ] **Step 10: Update `admin_list_licenses` JSON response**

In `app/routers/api.py::admin_list_licenses`, add `allow_http_webhook` to the response item dict:

```python
                "webhook_url": r.webhook_url,
                "webhook_url_source": r.webhook_url_source,
                "allow_http_webhook": bool(r.allow_http_webhook),
```

- [ ] **Step 11: Update `app/webhooks.py::deliver` resolution path**

Today `deliver()` calls `resolve_safe_address(url, allow_http=True)` unconditionally. Now it must pass the per-license value. The cleanest fix: add an `allow_http` kwarg to `deliver` and have callers pass `lic.allow_http_webhook`. Callers are: `try_deliver` (loads the URL+secret from the `WebhookDelivery` row), `deliver_status_change`, `deliver_update`, `deliver_deleted`, `test_webhook`.

For `try_deliver`: the `WebhookDelivery` row doesn't carry the flag. Easiest: read the live License row inside `try_deliver` (if `delivery.license_id` is set) and pass `lic.allow_http_webhook`. If the license was deleted (delivery for a deleted license), the URL was already validated at enqueue time and the URL/scheme is fixed — default `allow_http` to whether the URL itself is http:// (i.e. trust the enqueued URL's scheme).

Add to `app/webhooks.py::deliver`:

```python
def deliver(
    *, url: str, secret: str, event_type: str, data: dict[str, Any],
    timeout: float = 5.0,
    event_id: str | None = None,
    timestamp: int | None = None,
    allow_http: bool = False,
) -> tuple[bool, int | None, str | None]:
    """... existing docstring ...

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
        log.warning("webhook refused (see above): %s", url)
        return False, None, "refused:unsafe_url"
    # ... rest of function stays exactly as today ...
```

(Adding the explicit shape check before resolve makes the "refused" reason in the log/return easier to debug, since `resolve_safe_address` returns None for any of three causes.)

For `try_deliver`: load the License row and pass through:

```python
def try_deliver(db: Session, delivery_id: str) -> bool:
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
    # Live license carries the allow_http flag. If the license is gone
    # (delete-cascade fired this delivery), fall back to inferring from
    # the stored URL's scheme.
    allow_http = False
    if d.license_id:
        lic = db.query(License).filter_by(id=d.license_id).one_or_none()
        if lic is not None:
            allow_http = bool(lic.allow_http_webhook)
    if not allow_http:
        allow_http = d.url.startswith("http://")
    ok, status, err = deliver(
        url=d.url, secret=d.secret, event_type=d.event_type, data=data,
        event_id=d.id,
        allow_http=allow_http,
    )
    # ... rest of try_deliver stays ...
```

For `deliver_status_change`, `deliver_update`: take `lic.allow_http_webhook` from the in-memory license:

```python
def deliver_status_change(*, license_obj, previous_status):
    if not license_obj.webhook_url or not license_obj.webhook_secret:
        return None
    data = {...}
    return deliver(
        url=license_obj.webhook_url, secret=license_obj.webhook_secret,
        event_type=EVENT_STATUS_CHANGED, data=data,
        allow_http=bool(license_obj.allow_http_webhook),
    )
```

(Same shape for `deliver_update`. `deliver_deleted` doesn't have a live license — pass `allow_http=url.startswith("http://")` to preserve enqueue-time behaviour.)

For `test_webhook` in `app/services/licenses.py`:

```python
def test_webhook(lic: License) -> WebhookTestResult:
    if not lic.webhook_url or not lic.webhook_secret:
        raise ValidationFailed("no webhook configured")
    ok, status, err = wh.deliver(
        url=lic.webhook_url, secret=lic.webhook_secret,
        event_type="license.test",
        data={
            "license_id": lic.id, "key": lic.key,
            "product_slug": lic.product.slug,
            "customer_email": lic.customer.email,
            "test": True,
        },
        allow_http=bool(lic.allow_http_webhook),
    )
    return WebhookTestResult(ok=ok, status=status, error=err)
```

- [ ] **Step 12: Run the new tests + full suite**

```bash
pytest tests/test_phase3_deploy.py -v
pytest -q
```

Expected: 4 new tests pass; full suite remains green (existing webhook tests that use https or that set `allow_http_webhook=True` in the test fixture data must continue to work — read tests/test_webhooks.py to confirm no test relies on an http URL succeeding without the flag).

If tests in `tests/test_webhooks.py` break because they used http:// URLs without the flag: those tests either (a) need to switch to https://example.test (the autouse DNS fixture already covers it) OR (b) need to issue with `allow_http_webhook=True`. Adjust whichever is cleaner per test.

- [ ] **Step 13: Commit**

```bash
git add app/models.py app/security.py app/services/check.py app/services/licenses.py app/routers/admin_ui/licenses.py app/routers/api.py app/templates/product_detail.html app/static/admin.js app/webhooks.py alembic/versions/*_allow_http_webhook.py tests/test_phase3_deploy.py tests/test_webhooks.py
git commit -m "$(cat <<'EOF'
H5: HTTPS-only webhooks by default; per-license allow_http opt-in

New licenses.allow_http_webhook column (default False). Webhook URL
validation defaults to HTTPS-only; ticking the admin-UI checkbox
flips the flag for that license, allowing http:// (intended for
customer-LAN installs). Migration backfills True for existing rows
whose webhook_url already starts with http:// so behaviour does not
regress.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: H6 — Caddyfile trusted_proxies + security headers

**Files:**
- Modify: `deploy/gcp/Caddyfile`

No code tests apply here (config file). The install.sh script already runs `caddy validate` as part of the deploy.

- [ ] **Step 1: Read the current Caddyfile**

```bash
cat deploy/gcp/Caddyfile
```

Expect a small file with `${ADMIN_EMAIL}` global, a `${LICENSE_HOST}` site block with `reverse_proxy 127.0.0.1:8800`, and an access log.

- [ ] **Step 2: Replace `deploy/gcp/Caddyfile` with the hardened version**

```caddyfile
{
    email ${ADMIN_EMAIL}
    servers {
        # Caddy only honors X-Forwarded-For / Forwarded from these source
        # ranges. private_ranges covers RFC1918 + loopback + link-local +
        # IPv6 ULA, which is exactly our deploy: clients hit Caddy, Caddy
        # connects to uvicorn over loopback. Spoofed XFF from real clients
        # is stripped before it reaches the upstream.
        trusted_proxies static private_ranges
    }
}

${LICENSE_HOST} {
    encode zstd gzip

    # Security headers on every response. Belt-and-braces alongside the
    # in-app dropping of XFF parsing (Phase 2 H1). The app already serves
    # HTTPS-only via Let's Encrypt; HSTS pins that posture in the browser
    # for two years even if the cert later goes self-signed.
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "no-referrer"
        # Hide the Caddy version banner.
        -Server
    }

    reverse_proxy 127.0.0.1:8800

    log {
        output file /var/log/caddy/access.log {
            roll_size 50mb
            roll_keep 5
        }
        format json
    }
}
```

- [ ] **Step 3: Validate with `caddy validate` (locally if you have caddy installed, otherwise skip — the deploy will catch it)**

```bash
caddy validate --config deploy/gcp/Caddyfile --adapter caddyfile
```

Expected: `Valid configuration`. If `caddy` isn't installed locally, `install.sh` runs the same command on the VM and will fail-fast if the file is malformed.

- [ ] **Step 4: Commit**

```bash
git add deploy/gcp/Caddyfile
git commit -m "$(cat <<'EOF'
H6: Caddyfile trusted_proxies + security headers

Add trusted_proxies private_ranges so Caddy strips client-spoofed XFF
before it reaches uvicorn (belt-and-braces alongside H1's in-app XFF
drop). Add HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-
Policy, and -Server to every response. No app-side change required.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Version bump to v0.23.0

**Files:**
- Modify: `app/__init__.py` → `"0.23.0"`
- Modify: `pyproject.toml` → `version = "0.23.0"`

- [ ] **Step 1: Bump both files**

```python
# app/__init__.py
__version__ = "0.23.0"
```

```toml
# pyproject.toml
version = "0.23.0"
```

- [ ] **Step 2: Run full suite**

```bash
pytest -q
```

Expected: green.

- [ ] **Step 3: Commit**

```bash
git add app/__init__.py pyproject.toml
git commit -m "$(cat <<'EOF'
chore: bump version to 0.23.0

Phase 3 network/deploy hardening: H5 (HTTPS-only webhooks with per-
license allow_http opt-in) and H6 (Caddyfile trusted_proxies +
security headers).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## End-of-phase check

- [ ] `pytest -q` green.
- [ ] `alembic upgrade head` on a fresh sqlite confirms the three phases' migrations chain cleanly.
- [ ] Read `deploy/gcp/Caddyfile` in the repo — it should match what's described above and `caddy validate` must succeed.
- [ ] Admin UI's webhook URL field shows the new HTTP-allow checkbox.

After Phase 3: Phase 4 (at-rest license-key hashing + JWT `aud` claim, breaking changes) plan gets written.
