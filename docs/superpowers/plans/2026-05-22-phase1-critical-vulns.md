# Phase 1 — Critical Vulns + Latent Bug Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three concrete security vulnerabilities (webhook hijack, DNS-rebind SSRF bypass, CSV injection) and fix the latent `_fire_deleted_webhook` ImportError; ship as v0.21.0.

**Architecture:** Surgical changes inside the existing FastAPI / SQLAlchemy structure. One Alembic migration (Vuln 1's new column). No new dependencies. TDD per fix; one commit per fix; final commit batches the version bump.

**Tech Stack:** FastAPI 0.115+, SQLAlchemy 2.0, Alembic, pytest 8.3, httpx (MockTransport for tests).

**Spec:** `docs/superpowers/specs/2026-05-22-security-hardening-design.md` (Phase 1 section).

**Branch:** `yg/Vulnerabilities-21-5-2026`.

---

## File Structure

**Modified:**
- `app/services/licenses.py` — add `_fire_deleted_webhook` (Task 1); `apply_webhook_config` writes `webhook_url_source` (Task 4).
- `app/routers/exports.py` — wrap every cell in `_csv_safe` (Task 2).
- `app/routers/admin_ui/events.py` — wrap every cell in `_csv_safe` (Task 2).
- `app/security.py` — add `resolve_safe_address` helper (Task 3).
- `app/webhooks.py` — `deliver` uses `resolve_safe_address`; rewrites URL to IP, sets Host header + SNI (Task 3).
- `app/models.py` — add `License.webhook_url_source` column (Task 4).
- `app/routers/api.py` — `CheckOut.webhook_secret` becomes `str | None`; only populated when source='self' (Task 4).
- `app/services/check.py` — refuse `public_url` updates when source='admin'; remove lazy-mint of secret (Task 4).
- `app/__init__.py`, `pyproject.toml` — bump to 0.21.0 (Task 5).

**Created:**
- `alembic/versions/<rev>_webhook_url_source.py` — schema + backfill for Vuln 1 (Task 4).
- `tests/test_phase1_security.py` — house for the new TDD tests (all four fixes).

---

## Task 1: Fix latent `_fire_deleted_webhook` ImportError (H4)

**Files:**
- Modify: `app/services/licenses.py` (add function)
- Modify: `tests/test_phase1_security.py` (new test file)

Current `app/services/products.py:112` imports `_fire_deleted_webhook` from `app.services.licenses` but the symbol does not exist. Any call to `delete_product` crashes with `ImportError`. Tests pass today because nothing exercises `delete_product` with webhooks on.

- [ ] **Step 1: Write the failing test**

Create `tests/test_phase1_security.py`:

```python
"""Phase 1 security hardening — TDD tests for vulns 1-3 + H4.

Each test exercises one specific fix and is added BEFORE the fix is
implemented (red-green-refactor).
"""
from __future__ import annotations

import hashlib
import hmac
from contextlib import contextmanager

import httpx
from fastapi.testclient import TestClient


@contextmanager
def _captured(monkeypatch, status: int = 200):
    sent: list[dict] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        sent.append({
            "url": str(req.url),
            "headers": dict(req.headers),
            "body": req.content.decode() if req.content else "",
        })
        return httpx.Response(status, content=b'{"ok":true}')

    test_client = httpx.Client(
        transport=httpx.MockTransport(_handler), follow_redirects=False,
    )
    import app.http_client as hc
    monkeypatch.setattr(hc, "_client", test_client)
    try:
        yield sent
    finally:
        test_client.close()


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


def _issue_with_webhook(client: TestClient, slug: str, webhook_url: str) -> str:
    """Issue a license via the admin UI form so we can set a webhook URL.
    Returns the license id."""
    cookies = _admin_login(client)
    r = _form_post(
        client, f"/admin/products/{slug}/licenses", cookies,
        data={
            "email": "alice@example.com",
            "plan": "standard",
            "max_users": "10",
            "valid_days": "30",
            "features_json": "{}",
            "webhook_url": webhook_url,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    # Parse the redirect for the issued license id.
    loc = r.headers["location"]
    assert "issued=" in loc, loc
    return loc.split("issued=")[1].split("&")[0]


# ---------- H4: _fire_deleted_webhook --------------------------------------


def test_delete_product_fires_webhooks_without_crashing(client, monkeypatch):
    """delete_product with a webhook-configured license must NOT raise
    ImportError on _fire_deleted_webhook (currently a latent crash) AND
    must deliver one license.deleted webhook per license."""
    _create_product(client)
    with _captured(monkeypatch) as sent:
        _issue_with_webhook(client, "asm", "https://customer.example.com/webhook")
        cookies = _admin_login(client)
        # delete the product → cascade-deletes the license → should fire webhook.
        r = _form_post(
            client, "/admin/products/asm/delete", cookies, follow_redirects=False,
        )
        assert r.status_code == 303, r.text
    deleted = [s for s in sent if "license.deleted" in s["headers"].get("x-license-server-event", "")]
    assert len(deleted) == 1, f"expected 1 license.deleted webhook, got {sent}"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_phase1_security.py::test_delete_product_fires_webhooks_without_crashing -v
```

Expected: ERROR or FAIL — `ImportError: cannot import name '_fire_deleted_webhook' from 'app.services.licenses'` when the cascade calls into `delete_product`.

- [ ] **Step 3: Add `_fire_deleted_webhook` to `app/services/licenses.py`**

Append at the end of the file (after `delete_licenses_bulk`):

```python
def _fire_deleted_webhook(snapshot: _DeletedLicenseSnapshot) -> None:
    """Post-commit webhook fan-out for a deleted license.

    Opens a fresh session, enqueues a WebhookDelivery, fires one attempt.
    Imported by app.services.products.delete_product, which calls this in
    a `schedule(...)` callback so it runs AFTER the cascade's commit.
    """
    if not (snapshot.webhook_url and snapshot.webhook_secret):
        return
    from app.db import SessionLocal
    s = SessionLocal()
    try:
        d = wh.enqueue(
            s, url=snapshot.webhook_url, secret=snapshot.webhook_secret,
            event_type=wh.EVENT_DELETED,
            data={
                "license_id": snapshot.license_id,
                "license_key": snapshot.key,
                "key": snapshot.key,
                "product_slug": snapshot.product_slug,
                "customer_email": snapshot.customer_email,
            },
            license_id=None,
            product_id=None,
        )
        s.commit()
        wh.attempt_in_fresh_session(d.id)
    except Exception:
        s.rollback()
        log.exception("post-commit deleted-webhook failed")
    finally:
        s.close()
```

- [ ] **Step 4: Run the test**

```bash
pytest tests/test_phase1_security.py::test_delete_product_fires_webhooks_without_crashing -v
```

Expected: PASS.

- [ ] **Step 5: Run full suite — no regression**

```bash
pytest -q
```

Expected: every existing test still green.

- [ ] **Step 6: Commit**

```bash
git add app/services/licenses.py tests/test_phase1_security.py
git commit -m "$(cat <<'EOF'
H4: implement _fire_deleted_webhook

Was imported by products.delete_product but never defined - delete_product
crashed with ImportError whenever any license under the product had a
webhook configured. Add the function (mirrors set_status's post-commit
attempt pattern) and a regression test that exercises the cascade.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: CSV-injection guard (Vuln 3)

**Files:**
- Modify: `app/routers/exports.py` (add `_csv_safe`, wrap each cell)
- Modify: `app/routers/admin_ui/events.py` (wrap each cell in events.csv)
- Modify: `tests/test_phase1_security.py` (add parametrized tests)

- [ ] **Step 1: Write the failing test**

Append to `tests/test_phase1_security.py`:

```python
# ---------- Vuln 3: CSV injection ------------------------------------------

import csv
import io

import pytest


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "=cmd|'/c calc'!A0",
        "+1+1",
        "-2+3",
        "@SUM(1+1)",
        "\t=danger",
        "\rdanger",
    ],
)
def test_customers_csv_neutralises_formula_chars(client, unsafe_value):
    """Customer name/email starting with formula characters must be prefixed
    with a single apostrophe so spreadsheets render them as literal text."""
    _create_product(client)
    # Issue a license with the dangerous name to seed a customer.
    r = client.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={
            "email": "alice@example.com", "name": unsafe_value,
            "plan": "standard", "valid_days": 30,
        },
    )
    assert r.status_code == 200, r.text
    r = client.get(
        "/v1/admin/exports/customers.csv",
        headers={"Authorization": "Bearer test-admin"},
    )
    assert r.status_code == 200
    rows = list(csv.reader(io.StringIO(r.text)))
    # Header + 1 row.
    assert len(rows) >= 2
    name_idx = rows[0].index("name")
    name_cell = rows[1][name_idx]
    assert name_cell.startswith("'"), f"name cell did not get sanitised: {name_cell!r}"
    assert name_cell[1:] == unsafe_value, "value beyond the apostrophe must be preserved verbatim"


def test_events_csv_neutralises_formula_chars(client):
    """Admin UI events.csv must apply the same guard."""
    _create_product(client)
    # Issue a license with a dangerous note — flows through the issued event.
    cookies = _admin_login(client)
    _ = _form_post(
        client, "/admin/products/asm/licenses", cookies,
        data={
            "email": "bob@example.com",
            "plan": "=evil",  # plan is admin-controlled, but exercises the path
            "max_users": "10",
            "valid_days": "30",
            "features_json": "{}",
        },
        follow_redirects=False,
    )
    r = client.get("/admin/events.csv", cookies=cookies, follow_redirects=False)
    assert r.status_code == 200
    rows = list(csv.reader(io.StringIO(r.text)))
    # find any cell starting with one of the unsafe chars (unprefixed)
    for row in rows[1:]:
        for cell in row:
            if cell and cell[0] in ("=", "+", "-", "@", "\t", "\r"):
                pytest.fail(f"unsanitised cell escaped into events.csv: {cell!r}")
```

- [ ] **Step 2: Run the tests — verify they fail**

```bash
pytest tests/test_phase1_security.py -v -k "csv"
```

Expected: FAIL — current code writes the value verbatim.

- [ ] **Step 3: Implement `_csv_safe` in `app/routers/exports.py`**

Insert after the imports, before `_csv_stream`:

```python
_UNSAFE_PREFIX: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(v: str) -> str:
    """Spreadsheet-formula guard. Excel/LibreOffice interpret a cell starting
    with `=`, `+`, `-`, `@`, TAB, or CR as a formula and execute it; prefixing
    with a single apostrophe is the canonical neutralisation.

    Applied to every cell emitted by every CSV export so a malicious customer
    name / email / payload that lands in the DB can't fire a formula when the
    admin opens the file."""
    if v and v[0] in _UNSAFE_PREFIX:
        return "'" + v
    return v
```

Then change `_csv_stream` to apply it to each cell. Current body:

```python
def _csv_stream(header: list[str], rows: Iterator[list[str]]) -> Iterator[bytes]:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    yield buf.getvalue().encode("utf-8")
    buf.seek(0)
    buf.truncate(0)
    for row in rows:
        writer.writerow(row)
        yield buf.getvalue().encode("utf-8")
        buf.seek(0)
        buf.truncate(0)
```

Replace the inner `writer.writerow(row)` so each cell passes through `_csv_safe`:

```python
def _csv_stream(header: list[str], rows: Iterator[list[str]]) -> Iterator[bytes]:
    """Yield CSV bytes in chunks. One buffer reused across rows so we never
    hold the whole file in memory. Every data cell is run through `_csv_safe`
    so a value starting with a formula character is neutralised."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    yield buf.getvalue().encode("utf-8")
    buf.seek(0)
    buf.truncate(0)
    for row in rows:
        writer.writerow([_csv_safe(cell) for cell in row])
        yield buf.getvalue().encode("utf-8")
        buf.seek(0)
        buf.truncate(0)
```

- [ ] **Step 4: Implement the same guard in `app/routers/admin_ui/events.py`**

Change `events_csv` so each cell goes through `_csv_safe`. Import the helper from `app.routers.exports`:

```python
import csv
import io
import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Event
from app.routers.admin_ui._deps import require_login, templates, utcnow
from app.routers.exports import _csv_safe  # NEW

router = APIRouter()


@router.get("/admin/events", response_class=HTMLResponse)
def events_list(request: Request, db: Session = Depends(get_db)) -> Response:
    require_login(request)
    rows = db.query(Event).order_by(Event.created_at.desc()).limit(500).all()
    return templates.TemplateResponse(request, "events.html", {"events": rows})


@router.get("/admin/events.csv")
def events_csv(request: Request, db: Session = Depends(get_db)) -> Response:
    require_login(request)
    rows = db.query(Event).order_by(Event.created_at.desc()).limit(5000).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["when", "type", "license_id", "product_id", "note", "payload"])
    for e in rows:
        payload = json.dumps(e.payload or {}, separators=(",", ":"))
        w.writerow([
            _csv_safe(e.created_at.strftime("%Y-%m-%d %H:%M:%S")),
            _csv_safe(e.type),
            _csv_safe(e.license_id or ""),
            _csv_safe(e.product_id or ""),
            _csv_safe(e.note or ""),
            _csv_safe(payload),
        ])
    filename = f"events-{utcnow().strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(
        buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
```

- [ ] **Step 5: Run the tests**

```bash
pytest tests/test_phase1_security.py -v -k "csv"
```

Expected: PASS.

- [ ] **Step 6: Run full suite**

```bash
pytest -q
```

Expected: green. (Existing `tests/test_exports.py` tests still pass — `_csv_safe` is a no-op for safe values.)

- [ ] **Step 7: Commit**

```bash
git add app/routers/exports.py app/routers/admin_ui/events.py tests/test_phase1_security.py
git commit -m "$(cat <<'EOF'
Vuln 3: neutralise CSV-formula-injection in every CSV export

Customer name, email, event payload, and event note can carry attacker-
controlled values (esp. via Stripe checkout email). Excel/LibreOffice
interpret leading = + - @ TAB CR as formulas. Prefix any such cell with
an apostrophe in _csv_stream + events_csv so the formula stays literal
when the admin opens the file.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: DNS-pin webhook delivery (Vuln 2)

**Files:**
- Modify: `app/security.py` (add `resolve_safe_address`)
- Modify: `app/webhooks.py` (use it in `deliver`)
- Modify: `tests/test_phase1_security.py` (add DNS-rebind regression test)

The current `is_safe_for_delivery` resolves DNS, returns a verdict, then `httpx` does its own resolution at connect time. An attacker controlling DNS with low TTL can serve a public IP for the safety check and an internal IP for the actual connect. The fix: resolve once, connect by IP, set the `Host` header and TLS SNI to the original hostname.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_phase1_security.py`:

```python
# ---------- Vuln 2: DNS-rebinding bypass -----------------------------------

import socket


def test_webhook_delivery_pins_resolved_ip(client, monkeypatch):
    """Mock getaddrinfo to return one IP, then assert httpx receives a
    request whose URL host is that IP (not the original hostname) and whose
    Host header carries the original hostname. Proves the deliver path
    resolves once and connects by IP, defeating DNS-rebinding."""
    # Capture what getaddrinfo says for the receiver hostname.
    real_getaddrinfo = socket.getaddrinfo

    def _fake_getaddrinfo(host, port, *args, **kwargs):
        if host == "customer.example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.5", port or 0))]
        return real_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

    _create_product(client)
    with _captured(monkeypatch) as sent:
        lid = _issue_with_webhook(client, "asm", "https://customer.example.com/wh")
        cookies = _admin_login(client)
        # disable → fires a status-change webhook
        r = _form_post(
            client, f"/admin/licenses/{lid}/disable", cookies, follow_redirects=False,
        )
        assert r.status_code == 303
    assert sent, "no webhook fired"
    req = sent[-1]
    # URL must contain the pinned IP, not the hostname.
    assert "203.0.113.5" in req["url"], f"request url did not use pinned IP: {req['url']}"
    assert "customer.example.com" not in req["url"], (
        f"hostname leaked into url; DNS-rebind window still open: {req['url']}"
    )
    # Host header must still be the original hostname so the receiver
    # virtual-hosts correctly and TLS SNI matches the cert.
    assert req["headers"].get("host") == "customer.example.com", req["headers"]


def test_webhook_refused_when_dns_resolves_only_to_private(client, monkeypatch):
    """If every A/AAAA the hostname returns is private/loopback/link-local,
    deliver must refuse before opening any socket."""
    real_getaddrinfo = socket.getaddrinfo

    def _fake_getaddrinfo(host, port, *args, **kwargs):
        if host == "bad.example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", port or 0))]
        return real_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

    _create_product(client)
    with _captured(monkeypatch) as sent:
        lid = _issue_with_webhook(client, "asm", "https://bad.example.com/wh")
        cookies = _admin_login(client)
        r = _form_post(
            client, f"/admin/licenses/{lid}/disable", cookies, follow_redirects=False,
        )
        assert r.status_code == 303
    assert not sent, f"webhook fired despite link-local DNS: {sent}"
```

- [ ] **Step 2: Run the tests — verify they fail**

```bash
pytest tests/test_phase1_security.py -v -k "pins_resolved_ip or refused_when_dns"
```

Expected: FAIL on the first test (hostname survives into the URL).

- [ ] **Step 3: Add `resolve_safe_address` helper in `app/security.py`**

Append to the end of `app/security.py`:

```python
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
        return None
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host:
        return None
    port = parts.port or (443 if parts.scheme == "https" else 80)
    # Literal IPs short-circuit DNS but still get the private-range check.
    try:
        ipaddress.ip_address(host)
        if _ip_is_private(host):
            return None
        return host, port, parts.scheme, host
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return None
    for _fam, _t, _p, _c, sockaddr in infos:
        addr = sockaddr[0]
        if not _ip_is_private(addr):
            return addr, port, parts.scheme, host
    return None
```

- [ ] **Step 4: Switch `app/webhooks.py::deliver` to the pinned path**

Replace the SSRF-guard + post block (top of `deliver`, currently:

```python
    ok_url, reason = is_safe_for_delivery(url, allow_http=True)
    if not ok_url and reason and reason.startswith(("unsafe_url_shape", "resolves_to_private")):
        log.error("refusing webhook to unsafe url: %s (%s)", url, reason)
        return False, None, f"refused:{reason}"
```

) with:

```python
    resolved = resolve_safe_address(url, allow_http=True)
    if resolved is None:
        log.error("refusing webhook to unsafe url: %s", url)
        return False, None, "refused:unsafe_url"
    ip, port, scheme, host = resolved
```

Update the import line at the top of `app/webhooks.py`:

```python
from app.security import resolve_safe_address
```

(Drop the now-unused `is_safe_for_delivery` import.)

Now build the pinned URL + headers. Replace the `r = get_client().post(url, ...)` block with:

```python
    # Rewrite URL host → literal IP so httpx's own resolver can't change
    # answers between our check and connect. Preserve the original hostname
    # in the Host header + TLS SNI so virtual-hosting and certs still work.
    ip_for_url = f"[{ip}]" if ":" in ip else ip
    pinned_url = f"{scheme}://{ip_for_url}:{port}{urlsplit(url).path or '/'}"
    if urlsplit(url).query:
        pinned_url += "?" + urlsplit(url).query
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
```

Add the `urlsplit` import at the top of `app/webhooks.py` if not present:

```python
from urllib.parse import urlsplit
```

- [ ] **Step 5: Run the new tests**

```bash
pytest tests/test_phase1_security.py -v -k "pins_resolved_ip or refused_when_dns"
```

Expected: PASS.

- [ ] **Step 6: Run full suite**

```bash
pytest -q
```

Expected: green. Existing webhook tests (`tests/test_webhooks.py`) use `MockTransport`, which doesn't go through real DNS, but `_handler` will now receive an IP-shaped URL plus a `Host` header. Most assertions there are on body / signature, not the literal URL host — verify nothing breaks. If a test asserts on the URL hostname, change it to assert on `Host` header instead.

- [ ] **Step 7: Commit**

```bash
git add app/security.py app/webhooks.py tests/test_phase1_security.py
git commit -m "$(cat <<'EOF'
Vuln 2: DNS-pin webhook delivery

is_safe_for_delivery resolved DNS then handed the URL to httpx which
re-resolved at connect time - a low-TTL attacker domain could return a
public IP for the safety check and 169.254.169.254 (or RFC1918) for the
actual request. Add resolve_safe_address to resolve once, then rewrite
the request URL to the literal IP while preserving Host + SNI so cert
validation and virtual-hosting still work.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Webhook URL provenance + secret gating (Vuln 1)

**Files:**
- Create: `alembic/versions/<rev>_webhook_url_source.py` (new migration)
- Modify: `app/models.py` (add column)
- Modify: `app/services/licenses.py` (write source on every URL write)
- Modify: `app/services/check.py` (refuse override; drop lazy mint)
- Modify: `app/routers/api.py` (gate `webhook_secret` in CheckOut)
- Modify: `tests/test_phase1_security.py` (4 new tests)

This is the biggest task: introduces a column + behaviour change at the public `/v1/check` boundary.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_phase1_security.py`:

```python
# ---------- Vuln 1: webhook hijack + secret leak ---------------------------


def test_v1check_does_not_overwrite_admin_set_webhook_url(client):
    """A license-key holder calling /v1/check with public_url must NOT
    silently overwrite a webhook_url set by the admin."""
    _create_product(client)
    cookies = _admin_login(client)
    # Admin issues a license + sets the webhook URL.
    r = _form_post(
        client, "/admin/products/asm/licenses", cookies,
        data={
            "email": "alice@example.com", "plan": "standard",
            "max_users": "10", "valid_days": "30", "features_json": "{}",
            "webhook_url": "https://admin.example.com/notify",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    # Grab the issued key from the admin product-detail page (licenses are
    # rendered there). Cheapest path: the JSON admin API.
    r = client.get(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
    )
    assert r.status_code == 200
    items = r.json()["items"]
    assert items, r.json()
    key = items[0]["key"]
    # Now an attacker holding the key tries to redirect the webhook.
    r = client.post(
        "/v1/check",
        json={
            "key": key, "install_id": "ii-1", "version": "1.0",
            "public_url": "https://attacker.tld/sink",
        },
    )
    # The response must be a refusal (409 — locked) OR a 200 with the URL
    # unchanged. The spec picks 409 for clarity.
    assert r.status_code == 409, r.text
    # Re-fetch the license; URL must still be the admin one.
    r = client.get(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
    )
    items = r.json()["items"]
    assert items[0].get("webhook_url") == "https://admin.example.com/notify"


def test_v1check_secret_not_returned_when_admin_set(client):
    """When the webhook URL was set by the admin, /v1/check must NOT
    include webhook_secret in the response — only the original receiver
    (the customer's HTTP receiver) should have learned the secret, via
    the one-time-display in the admin UI."""
    _create_product(client)
    cookies = _admin_login(client)
    _ = _form_post(
        client, "/admin/products/asm/licenses", cookies,
        data={
            "email": "alice@example.com", "plan": "standard",
            "max_users": "10", "valid_days": "30", "features_json": "{}",
            "webhook_url": "https://customer.example.com/wh",
        },
        follow_redirects=False,
    )
    r = client.get(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
    )
    key = r.json()["items"][0]["key"]
    r = client.post(
        "/v1/check",
        json={"key": key, "install_id": "ii-1", "version": "1.0"},
    )
    assert r.status_code == 200, r.text
    assert r.json().get("webhook_secret") in (None, "")


def test_v1check_self_registered_flow_still_works(client):
    """A license issued WITHOUT a webhook can still self-register via
    /v1/check; secret is returned so the customer's app can verify
    incoming webhooks."""
    _create_product(client)
    cookies = _admin_login(client)
    _ = _form_post(
        client, "/admin/products/asm/licenses", cookies,
        data={
            "email": "alice@example.com", "plan": "standard",
            "max_users": "10", "valid_days": "30", "features_json": "{}",
        },
        follow_redirects=False,
    )
    r = client.get(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
    )
    key = r.json()["items"][0]["key"]
    r = client.post(
        "/v1/check",
        json={
            "key": key, "install_id": "ii-1", "version": "1.0",
            "public_url": "https://customer.example.com/wh",
        },
    )
    assert r.status_code == 200, r.text
    assert r.json().get("webhook_secret"), r.json()


def test_v1check_does_not_mint_secret_when_no_url(client):
    """A license with no webhook URL must NOT receive a lazy-minted secret
    on /v1/check; the secret only exists alongside a real URL."""
    _create_product(client)
    cookies = _admin_login(client)
    _ = _form_post(
        client, "/admin/products/asm/licenses", cookies,
        data={
            "email": "alice@example.com", "plan": "standard",
            "max_users": "10", "valid_days": "30", "features_json": "{}",
        },
        follow_redirects=False,
    )
    r = client.get(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
    )
    key = r.json()["items"][0]["key"]
    r = client.post(
        "/v1/check",
        json={"key": key, "install_id": "ii-1", "version": "1.0"},
    )
    assert r.status_code == 200
    # No URL -> no secret in response.
    assert r.json().get("webhook_secret") in (None, "")
```

- [ ] **Step 2: Run the tests — verify they fail**

```bash
pytest tests/test_phase1_security.py -v -k "v1check"
```

Expected: all four FAIL (current behaviour overrides admin URLs and returns secret unconditionally).

- [ ] **Step 3: Add the column to `app/models.py`**

In the `License` model, add (right after `webhook_secret`):

```python
    webhook_url_source: Mapped[str] = mapped_column(
        String(16), default="self", nullable=False,
    )
```

Add a CheckConstraint to `__table_args__`:

```python
    __table_args__ = (
        CheckConstraint(
            f"status IN {LICENSE_STATUSES!r}",
            name="ck_licenses_status",
        ),
        CheckConstraint(
            "webhook_url_source IN ('admin','self')",
            name="ck_licenses_webhook_url_source",
        ),
    )
```

- [ ] **Step 4: Write the Alembic migration**

Find the current head:

```bash
alembic heads
```

Take note (e.g. `e06b4aa2e5b1`). Create the migration:

```bash
alembic revision -m "webhook url source"
```

Open the generated file under `alembic/versions/` and replace its body:

```python
"""webhook url source

Revision ID: <leave the generated id>
Revises: <leave the generated down_revision>
Create Date: <leave the generated date>

Locks down admin-configured webhook URLs against /v1/check overrides.

Adds licenses.webhook_url_source with two values:
  - 'admin': URL was set via admin UI / admin JSON API. /v1/check refuses
    public_url updates against these rows.
  - 'self':  URL was set (or will be set) via /v1/check's public_url. /v1/check
    may update the URL freely.

Backfill: every existing row with a non-NULL webhook_url is set to 'admin'
(locked); rows with NULL webhook_url stay at the 'self' default. Admin can
flip via UI on a per-license basis if they want client self-registration.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "<keep generated>"
down_revision: str | Sequence[str] | None = "<keep generated>"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("licenses") as batch:
        batch.add_column(
            sa.Column(
                "webhook_url_source",
                sa.String(16),
                nullable=False,
                server_default=sa.text("'self'"),
            )
        )
        batch.create_check_constraint(
            "ck_licenses_webhook_url_source",
            "webhook_url_source IN ('admin','self')",
        )
    # Backfill: existing rows with a URL are admin-managed.
    op.execute(
        "UPDATE licenses SET webhook_url_source = 'admin' "
        "WHERE webhook_url IS NOT NULL"
    )


def downgrade() -> None:
    with op.batch_alter_table("licenses") as batch:
        batch.drop_constraint("ck_licenses_webhook_url_source", type_="check")
        batch.drop_column("webhook_url_source")
```

Replace the two `<keep generated>` strings with what alembic put there.

- [ ] **Step 5: Update `app/services/licenses.py::apply_webhook_config`**

Replace the function body with:

```python
def apply_webhook_config(
    lic: License, *, url: str | None, rotate: bool, mint_on_url_change: bool,
    source: str = "admin",
) -> None:
    """Mutate `lic.webhook_url` + `lic.webhook_secret` + `lic.webhook_url_source`
    per rotate semantics.

    `source` records who wrote the URL: 'admin' for admin UI / JSON API,
    'self' for /v1/check self-registration. /v1/check refuses overrides
    against rows whose source is 'admin'.

    Mints a fresh secret when:
      - `rotate=True` (caller explicitly asked), OR
      - the license has no secret yet (first-time set), OR
      - `mint_on_url_change=True` AND the URL actually changed.

    `url=None` clears all three fields. Caller commits.
    """
    if url:
        if not is_safe_url_shape(url, allow_http=True):
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
    else:
        lic.webhook_url = None
        lic.webhook_secret = None
        lic.webhook_url_source = "self"
```

Then update `issue_license` (same file) to write the source when a webhook is set:

```python
    webhook_url_clean = (webhook_url or "").strip() or None
    if webhook_url_clean and not is_safe_url_shape(webhook_url_clean, allow_http=True):
        raise Unsafe("unsafe webhook url")
    webhook_secret_value = wh.generate_secret() if webhook_url_clean else None
    webhook_source_value = "admin" if webhook_url_clean else "self"
```

Pass `webhook_url_source=webhook_source_value` into the `License(...)` constructor a few lines down.

- [ ] **Step 6: Update `app/services/check.py::check_license`**

Replace the `public_url` block + the lazy-mint block. Current shape:

```python
    if public_url is not None and public_url.strip():
        candidate = public_url.strip().rstrip("/")
        if len(candidate) > 500 or not is_safe_url_shape(candidate, allow_http=True):
            raise CheckRejected("invalid_public_url", http_status=400)
        if lic.webhook_url != candidate:
            ...
            lic.webhook_url = candidate

    if not lic.webhook_secret:
        lic.webhook_secret = webhooks.generate_secret()
```

New shape:

```python
    if public_url is not None and public_url.strip():
        candidate = public_url.strip().rstrip("/")
        if len(candidate) > 500 or not is_safe_url_shape(candidate, allow_http=True):
            raise CheckRejected("invalid_public_url", http_status=400)
        if lic.webhook_url != candidate:
            # Admin-managed URLs are locked against /v1/check overrides.
            if lic.webhook_url_source == "admin":
                log.warning(
                    "license %s refused public_url override of admin-set URL", lic.id,
                )
                db.add(Event(
                    license_id=lic.id, product_id=lic.product_id,
                    type="webhook:override_refused",
                    payload={"attempted_url": candidate, "kept_url": lic.webhook_url},
                    note="service/check",
                ))
                db.commit()
                raise CheckRejected("webhook_url_locked", http_status=409)
            log.info("license %s webhook_url updated to %s", lic.id, candidate)
            db.add(Event(
                license_id=lic.id, product_id=lic.product_id,
                type="webhook:self-registered",
                payload={
                    "previous_url": lic.webhook_url,
                    "new_url": candidate,
                    "via": "v1_check",
                },
                note="service/check",
            ))
            lic.webhook_url = candidate
            lic.webhook_url_source = "self"
            # First time the customer self-registers → mint a secret so the
            # response can carry it. Re-self-registration of the same URL
            # leaves the existing secret in place.
            if not lic.webhook_secret:
                lic.webhook_secret = webhooks.generate_secret()
```

Remove the unconditional `if not lic.webhook_secret: lic.webhook_secret = webhooks.generate_secret()` block below. (Lazy mint now only happens inside the self-register branch above.)

- [ ] **Step 7: Update `app/routers/api.py::CheckOut`**

Make `webhook_secret` optional and only populate it when source is `self`:

```python
class CheckOut(BaseModel):
    jwt: str
    valid_until: datetime
    features: dict
    max_users: int
    license_id: str
    product: str
    # Only present when the URL is self-registered (source='self'); admin-set
    # URLs do not expose the secret over /v1/check.
    webhook_secret: str | None = None
```

And in the `check` endpoint:

```python
    return CheckOut(
        jwt=result.jwt,
        valid_until=lic.valid_until,
        features=lic.features or {},
        max_users=lic.max_users,
        license_id=lic.id,
        product=lic.product.slug,
        webhook_secret=(
            lic.webhook_secret if lic.webhook_url_source == "self" else None
        ),
    )
```

- [ ] **Step 8: Update the admin JSON API to return `webhook_url`**

The Vuln 1 test re-fetches licenses via `/v1/admin/products/asm/licenses` and expects `webhook_url` in the response. Adjust the list comprehension in `app/routers/api.py::admin_list_licenses`:

```python
        "items": [
            {
                "id": r.id, "key": r.key, "plan": r.plan, "status": r.status,
                "max_users": r.max_users, "features": r.features,
                "valid_until": r.valid_until.isoformat(),
                "customer": r.customer.email, "customer_name": r.customer.name,
                "created_at": r.created_at.isoformat(),
                "webhook_url": r.webhook_url,
                "webhook_url_source": r.webhook_url_source,
            }
            for r in page.items
        ],
```

- [ ] **Step 9: Run the new tests**

```bash
pytest tests/test_phase1_security.py -v -k "v1check"
```

Expected: PASS (all four).

- [ ] **Step 10: Run full suite**

```bash
pytest -q
```

Expected: green. If `tests/test_check.py::test_check_returns_webhook_secret` fails, it's because that test issues a license without a webhook URL and expects the response to carry the auto-minted secret. Per Vuln 1 the auto-mint is gone; update that test to either set a `public_url` first (self-register path) or to assert `webhook_secret is None`.

- [ ] **Step 11: Commit**

```bash
git add app/models.py alembic/versions/*_webhook_url_source.py app/services/licenses.py app/services/check.py app/routers/api.py tests/test_phase1_security.py tests/test_check.py
git commit -m "$(cat <<'EOF'
Vuln 1: webhook URL provenance + gated secret exposure

License-key holders could (a) silently overwrite an admin-configured
webhook URL and (b) read the webhook_secret via /v1/check. Track
provenance on a new licenses.webhook_url_source column; refuse public_url
updates against 'admin' rows; drop the lazy-mint of webhook_secret;
return webhook_secret only when source='self' (the customer who can
legitimately receive it).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Version bump to v0.21.0

**Files:**
- Modify: `app/__init__.py`
- Modify: `pyproject.toml`

- [ ] **Step 1: Bump `app/__init__.py`**

```python
__version__ = "0.21.0"
```

- [ ] **Step 2: Bump `pyproject.toml`**

Change the `version` line from `"0.16.4"` (drifted) to `"0.21.0"`. This also fixes the pre-existing drift between the two files.

- [ ] **Step 3: Run full suite one last time**

```bash
pytest -q
```

Expected: green.

- [ ] **Step 4: Commit**

```bash
git add app/__init__.py pyproject.toml
git commit -m "$(cat <<'EOF'
chore: bump version to 0.21.0

Phase 1 security hardening: vulns 1-3 + H4 latent bug. Also aligns
pyproject.toml (which had drifted to 0.16.4) with app/__init__ as the
source of truth.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## End-of-phase check

- [ ] Push branch + open PR (or fast-forward main if you don't gate this branch behind review):

```bash
git push -u origin yg/Vulnerabilities-21-5-2026
```

- [ ] Verify CI is green on the branch.

- [ ] Optionally tag and ship:

```bash
git tag v0.21.0
git push origin v0.21.0
./deploy.ps1
```

After ship, Phase 2's plan gets written (TOTP MFA + KEK gate + XFF + JWT claims).
