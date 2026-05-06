"""Outbound-webhook tests with mocked HTTP transport."""
from __future__ import annotations

import hashlib
import hmac
import importlib
import json
from contextlib import contextmanager
from io import BytesIO

import pytest
from fastapi.testclient import TestClient


@contextmanager
def _captured(monkeypatch, status: int = 200):
    """Patch urllib.request.urlopen to capture POST payloads sent by webhooks."""
    sent: list[dict] = []

    class _Resp:
        def __init__(self, code: int) -> None:
            self.status = code
            self._body = BytesIO(b'{"ok":true}')

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self) -> bytes:
            return self._body.read()

    def _fake_urlopen(req, timeout=None):
        sent.append({
            "url": req.full_url,
            "headers": dict(req.headers),
            "body": req.data.decode(),
        })
        return _Resp(status)

    import app.webhooks as wh
    monkeypatch.setattr(wh.urllib.request, "urlopen", _fake_urlopen)
    yield sent


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
    assert msg["headers"]["X-license-server-event"] == "license.status.changed"
    assert "X-license-server-signature" in msg["headers"]
    assert "X-license-server-event-id" in msg["headers"]
    payload = json.loads(msg["body"])
    assert payload["type"] == "license.status.changed"
    assert payload["data"]["previous_status"] == "active"
    assert payload["data"]["current_status"] == "disabled"


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


def test_signature_verifies_with_secret_in_db(client: TestClient, monkeypatch) -> None:
    _create_product(client)
    lid = _issue_via_ui(client, webhook_url="https://example.test/webhook")
    cookies = _admin_login(client)

    with _captured(monkeypatch) as sent:
        client.post(f"/admin/licenses/{lid}/disable", cookies=cookies, follow_redirects=False)
    msg = sent[0]
    sig_header = msg["headers"]["X-license-server-signature"]
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
