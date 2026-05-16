"""Outbound-webhook tests with mocked HTTP transport."""
from __future__ import annotations

import hashlib
import hmac
import importlib
import json
from contextlib import contextmanager

import httpx
import pytest
from fastapi.testclient import TestClient


@contextmanager
def _captured(monkeypatch, status: int = 200):
    """Capture outbound posts via httpx.MockTransport. The captured list
    keeps the pre-httpx contract: each entry is {url, headers, body} where
    headers are lowercased (HTTP/2 norm) and body is the JSON string."""
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
    # Set the module-level singleton directly. Callers do
    # `from app.http_client import get_client` at import time, so patching
    # `hc.get_client` wouldn't reach them; patching the underlying _client
    # global does (every get_client() call dereferences it).
    monkeypatch.setattr(hc, "_client", test_client)
    try:
        yield sent
    finally:
        test_client.close()


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    db_path = tmp_path / "license.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ADMIN_TOKEN", "test-admin")
    monkeypatch.setenv("SESSION_SECRET", "test-admin")
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.delenv("RESEND_API_KEY", raising=False)

    import app.config as cfg
    import app.db as db
    importlib.reload(cfg)
    importlib.reload(db)
    import app.webhooks as wh
    importlib.reload(wh)
    import app.api as api_mod
    importlib.reload(api_mod)
    import app.admin_ui as ui_mod
    importlib.reload(ui_mod)
    import app.main as m
    importlib.reload(m)
    db.init_db()
    return TestClient(m.app)


def _admin_login(client: TestClient) -> dict[str, str]:
    """Return a dict of cookies for the session-cookie path. Admin UI routes
    use the cookie; JSON API routes use the bearer token."""
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return {"asm_ls_session": r.cookies["asm_ls_session"]}


def _create_product(client: TestClient) -> None:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "Animal Shelter Manager", "key_prefix": "asm"},
    )
    assert r.status_code == 200, r.text


def _issue_via_ui(client: TestClient, *, webhook_url: str = "") -> str:
    """Issue a license via the admin UI form (the only path that accepts
    webhook_url today; JSON API to come later)."""
    cookies = _admin_login(client)
    form = {
        "email": "buyer@example.com",
        "plan": "standard",
        "max_users": "10",
        "valid_days": "30",
        "features_json": "{}",
    }
    if webhook_url:
        form["webhook_url"] = webhook_url
    r = client.post(
        "/admin/products/asm/licenses",
        data=form, cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    # Pull the issued license id from the redirect URL.
    loc = r.headers["location"]
    return loc.rsplit("issued=", 1)[1]


# ---------- pure crypto ---------------------------------------------------

def test_sign_is_hmac_sha256_of_timestamp_dot_body() -> None:
    import app.webhooks as wh
    secret = "whsec_abc"
    body = b'{"hello":"world"}'
    ts = 1700000000
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    assert wh.sign(secret, ts, body) == expected


def test_generate_secret_has_whsec_prefix() -> None:
    import app.webhooks as wh
    s = wh.generate_secret()
    assert s.startswith("whsec_")
    assert len(s) > 30  # non-trivial entropy


# ---------- delivery wiring -----------------------------------------------

def test_status_change_fires_webhook(client: TestClient, monkeypatch) -> None:
    _create_product(client)
    lid = _issue_via_ui(client, webhook_url="https://example.test/webhook")
    cookies = _admin_login(client)

    with _captured(monkeypatch) as sent:
        r = client.post(f"/admin/licenses/{lid}/disable", cookies=cookies, follow_redirects=False)
        assert r.status_code == 303

    assert len(sent) == 1
    msg = sent[0]
    assert msg["url"] == "https://example.test/webhook"
    assert msg["headers"]["x-license-server-event"] == "license.status.changed"
    assert "x-license-server-signature" in msg["headers"]
    assert "x-license-server-event-id" in msg["headers"]
    payload = json.loads(msg["body"])
    assert payload["type"] == "license.status.changed"
    assert payload["data"]["previous_status"] == "active"
    assert payload["data"]["current_status"] == "disabled"
    # Receivers (ASM) index tenants by license_key — pin its presence.
    assert payload["data"]["license_key"].startswith("asm_")


def test_no_webhook_when_url_unset(client: TestClient, monkeypatch) -> None:
    _create_product(client)
    lid = _issue_via_ui(client)  # no webhook_url
    cookies = _admin_login(client)

    with _captured(monkeypatch) as sent:
        r = client.post(f"/admin/licenses/{lid}/disable", cookies=cookies, follow_redirects=False)
        assert r.status_code == 303

    assert sent == []


def test_webhook_failure_does_not_break_admin_action(client: TestClient, monkeypatch) -> None:
    _create_product(client)
    lid = _issue_via_ui(client, webhook_url="https://example.test/webhook")
    cookies = _admin_login(client)

    # Receiver returns 5xx — admin action must still complete.
    with _captured(monkeypatch, status=500):
        r = client.post(f"/admin/licenses/{lid}/disable", cookies=cookies, follow_redirects=False)
        assert r.status_code == 303

    # Confirm the status actually flipped despite delivery failure.
    listing = client.get(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
    ).json()
    assert listing[0]["status"] == "disabled"


def test_delete_fires_license_deleted_webhook(client: TestClient, monkeypatch) -> None:
    _create_product(client)
    lid = _issue_via_ui(client, webhook_url="https://example.test/webhook")
    cookies = _admin_login(client)

    # Use the bulk-delete path -- same _delete_license helper that the per-row
    # /delete endpoint (PR #9) calls. Either route fires the webhook.
    with _captured(monkeypatch) as sent:
        r = client.post(
            "/admin/products/asm/licenses/delete",
            data={"license_ids": lid},
            cookies=cookies, follow_redirects=False,
        )
        assert r.status_code == 303

    assert len(sent) == 1
    payload = json.loads(sent[0]["body"])
    assert payload["type"] == "license.deleted"
    assert payload["data"]["license_id"] == lid
    assert payload["data"]["license_key"].startswith("asm_")


# ---------- regression: race between webhook delivery and DB commit -------
#
# The bug: _set_license_status / _delete_license used to fire the webhook
# AFTER db.flush() but BEFORE the route's db.commit(). Receivers calling
# back into /v1/check synchronously would open a fresh Session via
# Depends(get_db), see the OLD status (uncommitted change isn't visible
# cross-session), and get a 200 + JWT for the just-disabled license.
# Today's fix moves the commit into the helper itself, before the webhook
# delivery. These tests pin the new contract: from inside the webhook
# delivery the license is observable in its NEW state via a fresh
# /v1/check call (just like a real receiver would do).

def _get_license_key(lid: str) -> str:
    """Fetch a license's `key` field directly from the DB. The /admin UI's
    redirect carries the `lid` (UUID); /v1/check wants the `key`."""
    import app.db as db_mod
    from app.models import License
    with db_mod.SessionLocal() as session:
        return session.query(License).filter_by(id=lid).one().key


@contextmanager
def _reentrant_check(monkeypatch, client: TestClient, key: str):
    """MockTransport handler that synchronously calls /v1/check on the same
    TestClient. Mimics a real receiver doing a sanity-check phone-home from
    inside its webhook handler -- pins the post-commit visibility contract."""
    captured: list[tuple[int, dict]] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        r = client.post(
            "/v1/check",
            json={"key": key, "install_id": "test-install", "version": "1.0.0"},
        )
        try:
            captured.append((r.status_code, r.json()))
        except Exception:
            captured.append((r.status_code, {}))
        return httpx.Response(200, content=b'{"ok":true}')

    test_client = httpx.Client(
        transport=httpx.MockTransport(_handler), follow_redirects=False,
    )
    import app.http_client as hc
    # Set the module-level singleton directly. Callers do
    # `from app.http_client import get_client` at import time, so patching
    # `hc.get_client` wouldn't reach them; patching the underlying _client
    # global does (every get_client() call dereferences it).
    monkeypatch.setattr(hc, "_client", test_client)
    try:
        yield captured
    finally:
        test_client.close()


def test_disable_webhook_callback_sees_disabled_status(
    client: TestClient, monkeypatch
) -> None:
    """Receiver-callback regression: when the webhook fires for a status
    flip, a fresh /v1/check from inside the delivery must see the new
    status. Pre-fix: 200 + JWT for the just-disabled license. Post-fix:
    401 reason=disabled."""
    _create_product(client)
    lid = _issue_via_ui(client, webhook_url="https://example.test/webhook")
    key = _get_license_key(lid)
    cookies = _admin_login(client)

    with _reentrant_check(monkeypatch, client, key) as cb:
        r = client.post(
            f"/admin/licenses/{lid}/disable", cookies=cookies, follow_redirects=False
        )
        assert r.status_code == 303

    assert len(cb) == 1, "expected exactly one webhook -> /v1/check callback"
    status, body = cb[0]
    assert status == 401, f"receiver saw {status} {body}; expected 401 disabled"
    assert body.get("detail", {}).get("reason") == "disabled", body


def test_enable_webhook_callback_sees_active_status(
    client: TestClient, monkeypatch
) -> None:
    """Inverse direction: enabling a previously-disabled license. The
    receiver callback during the enable webhook must see status=active
    and get back a fresh JWT."""
    _create_product(client)
    lid = _issue_via_ui(client, webhook_url="https://example.test/webhook")
    key = _get_license_key(lid)
    cookies = _admin_login(client)

    # Flip to disabled first; suppress the disable webhook's callback noise.
    with _captured(monkeypatch):
        client.post(
            f"/admin/licenses/{lid}/disable", cookies=cookies, follow_redirects=False
        )

    # Now flip back to active and assert the inside-webhook /v1/check sees it.
    with _reentrant_check(monkeypatch, client, key) as cb:
        r = client.post(
            f"/admin/licenses/{lid}/enable", cookies=cookies, follow_redirects=False
        )
        assert r.status_code == 303

    assert len(cb) == 1
    status, body = cb[0]
    assert status == 200, f"receiver saw {status} {body}; expected 200 + JWT"
    assert "jwt" in body
    assert body.get("license_id") == lid


def test_delete_webhook_callback_sees_license_gone(
    client: TestClient, monkeypatch
) -> None:
    """Same race in the delete path: receiver callback during the
    license.deleted webhook must see the license gone (-> 401 invalid_key)."""
    _create_product(client)
    lid = _issue_via_ui(client, webhook_url="https://example.test/webhook")
    key = _get_license_key(lid)
    cookies = _admin_login(client)

    with _reentrant_check(monkeypatch, client, key) as cb:
        r = client.post(
            f"/admin/licenses/{lid}/delete", cookies=cookies, follow_redirects=False
        )
        assert r.status_code == 303

    assert len(cb) == 1
    status, body = cb[0]
    assert status == 401, f"receiver saw {status} {body}; expected 401 invalid_key"
    assert body.get("detail", {}).get("reason") == "invalid_key", body


# ---------- regression: form handlers auto-mint on first save -----------
#
# Bug report: "setting a webhook URL on a license that has no existing
# secret doesn't mint one automatically -- the admin has to tick Rotate
# and click Save again." The JSON API (POST /admin/api/.../webhook,
# v0.6.0) already handled this via _apply_webhook_config; the form-driven
# UI handlers must match. These tests pin both:
#   - POST /admin/licenses/{lid}/webhook  (Update button in modal)
#   - POST /admin/licenses/{lid}/edit     (Save / Apply button in modal)

def _read_license(lid: str):
    """Pull a fresh License row from the DB so assertions don't read a
    stale object cached in the test's session."""
    import app.db as db_mod
    from app.models import License
    with db_mod.SessionLocal() as session:
        return (
            session.query(License).filter_by(id=lid).one(),
        )[0]


def test_form_webhook_handler_auto_mints_on_first_save(
    client: TestClient, monkeypatch
) -> None:
    """No prior URL, no prior secret. Admin pastes URL, leaves Rotate
    unticked, clicks Update -> hits /admin/licenses/{lid}/webhook. The
    handler must mint a secret without a second pass."""
    _create_product(client)
    lid = _issue_via_ui(client)  # no webhook_url
    cookies = _admin_login(client)

    # Pre-condition: no secret yet.
    pre = _read_license(lid)
    assert pre.webhook_url is None
    assert pre.webhook_secret is None

    r = client.post(
        f"/admin/licenses/{lid}/webhook",
        data={"webhook_url": "https://example.test/webhook"},  # no rotate_secret
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text

    post = _read_license(lid)
    assert post.webhook_url == "https://example.test/webhook"
    assert post.webhook_secret is not None
    assert post.webhook_secret.startswith("whsec_"), post.webhook_secret


def test_form_edit_handler_auto_mints_on_first_save(
    client: TestClient, monkeypatch
) -> None:
    """Same flow but via the Save Changes button (POST /edit). Used to be
    inline duplicated logic; refactored to call _apply_webhook_config."""
    _create_product(client)
    lid = _issue_via_ui(client)
    cookies = _admin_login(client)

    pre = _read_license(lid)
    assert pre.webhook_secret is None

    # /edit takes the full license payload, not just webhook_url.
    r = client.post(
        f"/admin/licenses/{lid}/edit",
        data={
            "plan": pre.plan,
            "max_users": str(pre.max_users),
            "valid_until": pre.valid_until.strftime("%Y-%m-%d"),
            "features_json": "{}",
            "webhook_url": "https://example.test/webhook",
            # rotate_secret intentionally omitted
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    # Server flagged secret_changed -> redirect with ?webhook_lid so the
    # modal auto-opens with the secret revealed.
    assert "webhook_lid=" in r.headers["location"], r.headers["location"]

    post = _read_license(lid)
    assert post.webhook_url == "https://example.test/webhook"
    assert post.webhook_secret is not None
    assert post.webhook_secret.startswith("whsec_")


def test_form_webhook_handler_no_mint_when_url_unchanged_and_no_rotate(
    client: TestClient, monkeypatch
) -> None:
    """Re-saving the same URL without ticking Rotate must NOT change the
    secret -- otherwise every Update click would invalidate the receiver's
    persisted secret. (Form path uses mint_on_url_change=True, but the
    URL didn't change, so no mint.)"""
    _create_product(client)
    lid = _issue_via_ui(client, webhook_url="https://example.test/webhook")
    cookies = _admin_login(client)
    sec1 = _read_license(lid).webhook_secret

    r = client.post(
        f"/admin/licenses/{lid}/webhook",
        data={"webhook_url": "https://example.test/webhook"},
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert _read_license(lid).webhook_secret == sec1


def test_signature_verifies_with_secret_in_db(client: TestClient, monkeypatch) -> None:
    _create_product(client)
    lid = _issue_via_ui(client, webhook_url="https://example.test/webhook")
    cookies = _admin_login(client)

    with _captured(monkeypatch) as sent:
        client.post(f"/admin/licenses/{lid}/disable", cookies=cookies, follow_redirects=False)
    msg = sent[0]
    sig_header = msg["headers"]["x-license-server-signature"]
    parts = dict(p.split("=", 1) for p in sig_header.split(","))

    # Fetch the secret directly from DB.
    from sqlalchemy import select

    import app.db as db
    from app.models import License
    with db.SessionLocal() as session:
        secret = session.execute(select(License.webhook_secret)).scalar_one()

    expected = hmac.new(
        secret.encode(),
        f"{parts['t']}.".encode() + msg["body"].encode(),
        hashlib.sha256,
    ).hexdigest()
    assert hmac.compare_digest(expected, parts["v1"])


# ---------- regression: flash banners must render inside the modal --------
#
# UX bug (PR #18): redirects with ?webhook_lid= / ?webhook_test_lid= /
# ?issued= / ?edited= auto-open the license modal, but the matching banner
# was only rendered on the background page where the overlay covered it.
# Pin that the banner text now appears INSIDE the #license-modal div so
# the admin sees it without dismissing the dialog.

def _assert_in_modal(html: bytes, needle: bytes) -> None:
    modal_open = html.find(b'<div id="license-modal"')
    assert modal_open != -1, "license modal not rendered"
    assert html.find(needle, modal_open) != -1, (
        f"banner {needle!r} not found inside #license-modal"
    )


def test_webhook_update_banner_renders_inside_modal(client: TestClient) -> None:
    _create_product(client)
    lid = _issue_via_ui(client)
    cookies = _admin_login(client)

    r = client.post(
        f"/admin/licenses/{lid}/webhook",
        data={"webhook_url": "https://example.test/webhook"},
        cookies=cookies, follow_redirects=True,
    )
    assert r.status_code == 200
    _assert_in_modal(r.content, b"webhook configuration updated")


def test_webhook_test_ok_banner_renders_inside_modal(
    client: TestClient, monkeypatch
) -> None:
    _create_product(client)
    lid = _issue_via_ui(client, webhook_url="https://example.test/webhook")
    cookies = _admin_login(client)

    with _captured(monkeypatch, status=200):
        r = client.post(
            f"/admin/licenses/{lid}/webhook/test",
            cookies=cookies, follow_redirects=True,
        )
    assert r.status_code == 200
    _assert_in_modal(r.content, b"test webhook delivered (HTTP 200)")


def test_webhook_test_failure_banner_renders_inside_modal(
    client: TestClient, monkeypatch
) -> None:
    _create_product(client)
    lid = _issue_via_ui(client, webhook_url="https://example.test/webhook")
    cookies = _admin_login(client)

    with _captured(monkeypatch, status=500):
        r = client.post(
            f"/admin/licenses/{lid}/webhook/test",
            cookies=cookies, follow_redirects=True,
        )
    assert r.status_code == 200
    _assert_in_modal(r.content, b"test webhook failed")


def test_edited_banner_renders_inside_modal(client: TestClient) -> None:
    _create_product(client)
    lid = _issue_via_ui(client)
    cookies = _admin_login(client)
    pre = _read_license(lid)

    r = client.post(
        f"/admin/licenses/{lid}/edit",
        data={
            "plan": pre.plan,
            "max_users": str(pre.max_users),
            "valid_until": pre.valid_until.strftime("%Y-%m-%d"),
            "features_json": "{}",
        },
        cookies=cookies, follow_redirects=True,
    )
    assert r.status_code == 200
    _assert_in_modal(r.content, b"license updated")
