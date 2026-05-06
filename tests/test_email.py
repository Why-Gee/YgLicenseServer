"""Email-on-issue tests with mocked Resend HTTP transport."""
from __future__ import annotations

import importlib
import json
from contextlib import contextmanager
from io import BytesIO

import pytest
from fastapi.testclient import TestClient


@contextmanager
def _captured(monkeypatch, status: int = 200):
    """Patch urllib.request.urlopen to capture POST payloads."""
    sent: list[dict] = []

    class _Resp:
        def __init__(self, code: int) -> None:
            self.status = code
            self._body = BytesIO(b'{"id":"e_test"}')

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
            "body": json.loads(req.data.decode()),
        })
        return _Resp(status)

    import app.email as email_mod
    monkeypatch.setattr(email_mod.urllib.request, "urlopen", _fake_urlopen)
    yield sent


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
    assert msg["headers"]["Authorization"] == "Bearer re_test_key"
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
