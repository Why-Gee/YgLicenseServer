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
    allow_http_webhook is not set (the new safe default).
    Uses a non-forbidden hostname so only the scheme check matters."""
    _create_product(client)
    cookies = _admin_login(client)
    r = _form_post(
        client, "/admin/products/asm/licenses", cookies,
        data={
            "email": "alice@example.com", "plan": "standard",
            "max_users": "10", "valid_days": "30", "features_json": "{}",
            "webhook_url": "http://customer.example.com/wh",
            # no allow_http_webhook field
        },
        follow_redirects=False,
    )
    # Form handler returns a 303 to ?error=... on Unsafe
    assert r.status_code == 303, r.text
    assert "error=unsafe" in r.headers["location"], r.headers["location"]


def test_issue_with_http_webhook_accepted_when_allow_http_set(client):
    """Same call WITH allow_http_webhook=1 succeeds; license row is
    persisted with allow_http_webhook=True.
    Uses a non-forbidden hostname so only the scheme check matters."""
    _create_product(client)
    cookies = _admin_login(client)
    r = _form_post(
        client, "/admin/products/asm/licenses", cookies,
        data={
            "email": "alice@example.com", "plan": "standard",
            "max_users": "10", "valid_days": "30", "features_json": "{}",
            "webhook_url": "http://customer.example.com/wh",
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
        # Stored as Integer(1); truthy check is correct.
        assert bool(lic.allow_http_webhook) is True
        assert lic.webhook_url == "http://customer.example.com/wh"


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
        # Stored as Integer(0); falsy check is correct.
        assert bool(lic.allow_http_webhook) is False
        assert lic.webhook_url.startswith("https://")


def test_v1_check_public_url_http_rejected_unless_allow_http_set(client):
    """A client self-registering an http:// public_url via /v1/check is
    rejected by default; opting in (admin sets allow_http_webhook=True on
    the row) makes it succeed. This test asserts the default-reject.
    Uses a non-forbidden hostname so only the scheme check matters."""
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
    # Client tries to self-register an http URL (non-forbidden hostname,
    # so only the scheme blocks it when allow_http_webhook=False).
    r = client.post(
        "/v1/check",
        json={
            "key": key, "install_id": "ii-1", "version": "1.0",
            "public_url": "http://customer.example.com/wh",
        },
    )
    assert r.status_code == 400, r.text
    assert r.json().get("detail", {}).get("reason") == "invalid_public_url"
