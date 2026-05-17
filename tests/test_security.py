"""Phase-1 security regressions.

- SSRF URL-shape ingestion check rejects literal private/loopback addrs,
  *.local / *.internal suffixes, non-http(s) schemes.
- Admin bearer-token check is constant-time and rejects malformed headers.
- Session cookies expire after SESSION_MAX_AGE_SECONDS even if the
  signature is still valid.
- Stripe webhook idempotency: a redelivered event.id does not double-fire.
"""
from __future__ import annotations

import time
from typing import Any

import pytest
from fastapi.testclient import TestClient

# ----- is_safe_url_shape -------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/hook",
        "https://api.example.test/x",   # reserved TLD, OK at ingestion
        "http://example.com/hook",      # http allowed when allow_http=True
    ],
)
def test_url_shape_accepts(url: str) -> None:
    from app.security import is_safe_url_shape
    assert is_safe_url_shape(url, allow_http=True) is True


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/x",
        "http://127.0.0.1/x",
        "http://10.0.0.1/x",
        "http://192.168.1.1/x",
        "http://172.16.0.1/x",
        "http://169.254.169.254/latest/meta-data",  # cloud metadata
        "http://[::1]/x",
        "http://foo.local/x",
        "http://foo.internal/x",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "ftp://example.com/x",
        "https://",                    # no host
        "not a url",
    ],
)
def test_url_shape_rejects(url: str) -> None:
    from app.security import is_safe_url_shape
    assert is_safe_url_shape(url, allow_http=True) is False


def test_url_shape_requires_https_by_default() -> None:
    from app.security import is_safe_url_shape
    assert is_safe_url_shape("http://example.com/x") is False
    assert is_safe_url_shape("https://example.com/x") is True


def test_check_rejects_metadata_ssrf(client: TestClient) -> None:
    """/v1/check public_url must not let a license-holder register the
    cloud metadata endpoint as a webhook target."""
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200
    r = client.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={"email": "x@example.com", "valid_days": 30},
    )
    key = r.json()["key"]
    r = client.post("/v1/check", json={
        "key": key, "install_id": "i1", "version": "1.0.0",
        "public_url": "http://169.254.169.254/latest/meta-data/",
    })
    assert r.status_code == 400


# ----- admin bearer constant-time -----------------------------------------

def test_admin_bearer_rejects_close_but_wrong(client: TestClient) -> None:
    """Same length, single byte different. Old code returned 401 either way;
    this just pins that the new constant-time path still rejects."""
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admiN"},  # capital N at end
        json={"slug": "x", "name": "x", "key_prefix": "x"},
    )
    assert r.status_code == 401


def test_admin_bearer_rejects_missing_prefix(client: TestClient) -> None:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "test-admin"},  # no Bearer prefix
        json={"slug": "x", "name": "x", "key_prefix": "x"},
    )
    assert r.status_code == 401


# ----- session cookie expiry ---------------------------------------------

def test_session_cookie_expires_after_max_age(client: TestClient) -> None:
    """Forge an old-iat cookie -> _logged_in returns False -> redirect."""
    from app.admin_ui import SESSION_COOKIE, SESSION_MAX_AGE_SECONDS, _serializer
    old_iat = int(time.time()) - (SESSION_MAX_AGE_SECONDS + 60)
    cookie = _serializer().dumps({"ok": True, "iat": old_iat})
    r = client.get(
        "/admin",
        cookies={SESSION_COOKIE: cookie},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "login" in r.headers["location"]


def test_session_cookie_without_iat_rejected(client: TestClient) -> None:
    """Cookies issued by pre-fix code had no iat -> must be rejected so an
    attacker can't replay them indefinitely."""
    from app.admin_ui import SESSION_COOKIE, _serializer
    cookie = _serializer().dumps({"ok": True})  # no iat
    r = client.get(
        "/admin",
        cookies={SESSION_COOKIE: cookie},
        follow_redirects=False,
    )
    assert r.status_code == 303


# ----- Stripe idempotency -------------------------------------------------

def _make_stripe_event(event_id: str, *, customer_id: str = "cus_X") -> dict[str, Any]:
    return {
        "id": event_id,
        "type": "invoice.paid",
        "data": {
            "object": {
                "customer": customer_id,
                "customer_email": "buyer@example.com",
            }
        },
    }


def test_stripe_event_idempotent(client: TestClient, monkeypatch) -> None:
    """Same event.id delivered twice must not extend valid_until twice."""
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={
            "slug": "asm", "name": "ASM", "key_prefix": "asm",
            "stripe_webhook_secret": "whsec_test",
        },
    )
    assert r.status_code == 200

    import stripe
    fake_event = _make_stripe_event("evt_dup_1")
    monkeypatch.setattr(stripe.Webhook, "construct_event",
                        lambda payload, sig, secret: fake_event)

    # First delivery -> creates license + customer
    r1 = client.post(
        "/v1/products/asm/stripe-webhook",
        headers={"Stripe-Signature": "sig"},
        content=b"{}",
    )
    assert r1.status_code == 200
    assert r1.json().get("duplicate") is not True

    # Find the license + remember valid_until
    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        lic = s.query(License).first()
        assert lic is not None
        vu_after_first = lic.valid_until

    # Redelivery of same event.id -> short-circuit
    r2 = client.post(
        "/v1/products/asm/stripe-webhook",
        headers={"Stripe-Signature": "sig"},
        content=b"{}",
    )
    assert r2.status_code == 200
    assert r2.json().get("duplicate") is True

    # valid_until unchanged
    with SessionLocal() as s:
        lic = s.query(License).first()
        assert lic.valid_until == vu_after_first


# ----- CSRF ----------------------------------------------------------------


def test_csrf_rejects_missing_token(client: TestClient) -> None:
    """Form POST without csrf_token on a destructive admin endpoint -> 403."""
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    cookies = {"asm_ls_session": r.cookies["asm_ls_session"]}
    r = client.post(
        "/admin/logout",
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 403


def test_csrf_rejects_wrong_token(client: TestClient) -> None:
    """Wrong CSRF value, even with a valid session cookie -> 403. Pins the
    same-site-XSS / hostile-subdomain mitigation."""
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    cookies = {"asm_ls_session": r.cookies["asm_ls_session"]}
    r = client.post(
        "/admin/logout",
        data={"csrf_token": "deadbeef" * 8},
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 403


def test_csrf_accepts_correct_token(client: TestClient) -> None:
    """Sanity: with the right token the destructive POST succeeds."""
    from app.config import get_settings
    from app.security import csrf_token
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    cookies = {"asm_ls_session": r.cookies["asm_ls_session"]}
    tok = csrf_token(get_settings().session_secret, cookies["asm_ls_session"])
    r = client.post(
        "/admin/logout",
        data={"csrf_token": tok},
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert "/admin/login" in r.headers["location"]
