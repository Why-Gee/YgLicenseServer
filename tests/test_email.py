"""Email-on-issue tests with mocked Resend HTTP transport."""
from __future__ import annotations

import importlib
import json
from contextlib import contextmanager

import httpx
import pytest
from fastapi.testclient import TestClient


@contextmanager
def _captured(monkeypatch, status: int = 200):
    """Capture outbound posts via httpx.MockTransport. Replaces the shared
    `app.http_client.get_client()` with a transport-mocked client; the
    captured list mirrors the pre-httpx test contract (url + headers + body)."""
    sent: list[dict] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        sent.append({
            "url": str(req.url),
            "headers": dict(req.headers),
            "body": json.loads(req.content.decode()) if req.content else {},
        })
        return httpx.Response(status, content=b'{"id":"e_test"}')

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
    monkeypatch.setenv("RESEND_API_KEY", "re_test_key")
    monkeypatch.setenv("EMAIL_FROM", "onboarding@resend.dev")

    import app.config as cfg
    import app.db as db
    importlib.reload(cfg)
    importlib.reload(db)
    import app.email as em
    importlib.reload(em)
    import app.api as api_mod
    importlib.reload(api_mod)
    import app.stripe_webhook as sw
    importlib.reload(sw)
    import app.main as m
    importlib.reload(m)
    db.init_db()
    return TestClient(m.app)


def _create_product(client: TestClient) -> dict:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "Animal Shelter Manager", "key_prefix": "asm"},
    )
    assert r.status_code == 200, r.text
    return r.json()


def _issue(client: TestClient, email: str = "buyer@example.com") -> str:
    r = client.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={"email": email, "plan": "standard", "valid_days": 30},
    )
    assert r.status_code == 200, r.text
    return r.json()["key"]


def test_admin_issue_sends_email(client: TestClient, monkeypatch) -> None:
    _create_product(client)
    with _captured(monkeypatch) as sent:
        key = _issue(client, email="buyer@example.com")
    assert len(sent) == 1
    msg = sent[0]
    assert msg["url"] == "https://api.resend.com/emails"
    assert msg["headers"]["authorization"] == "Bearer re_test_key"
    assert msg["body"]["to"] == ["buyer@example.com"]
    assert "Animal Shelter Manager" in msg["body"]["subject"]
    assert key in msg["body"]["text"]
    assert msg["body"]["from"] == "Animal Shelter Manager <onboarding@resend.dev>"


def test_email_skipped_when_unconfigured(tmp_path, monkeypatch) -> None:
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
    import app.email as em
    importlib.reload(em)
    import app.api as api_mod
    importlib.reload(api_mod)
    import app.main as m
    importlib.reload(m)
    db.init_db()
    c = TestClient(m.app)

    c.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )

    with _captured(monkeypatch) as sent:
        c.post(
            "/v1/admin/products/asm/licenses",
            headers={"Authorization": "Bearer test-admin"},
            json={"email": "x@example.com", "plan": "standard", "valid_days": 30},
        )
    assert sent == []  # no http call attempted


def test_email_failure_does_not_break_issue(client: TestClient, monkeypatch) -> None:
    _create_product(client)
    with _captured(monkeypatch, status=500):
        # Should not raise even though Resend returned 5xx
        key = _issue(client, email="buyer@example.com")
    assert key.startswith("asm_")
