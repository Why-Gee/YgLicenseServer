"""Tests for the v1.0.3 follow-ups driven by
docs/v1.0-workouttracker-client-findings.md:

- Item 1: admin-UI button + POST /admin/licenses/{lid}/webhook/convert-to-self
  flips source='admin' to source='self', keeping URL, rotating secret.
- Item 2: webhook_url_source surfaces in the licenses-data JSON block so
  the admin UI can render a 'admin' / 'self' badge.
- Item 3: /v1/check no longer 409s on a public_url mismatch against an
  admin-set URL. Heartbeat continues, JWT minted, audit event emitted.
  (Covered in test_phase1_security.py; this file pins the new endpoint +
  the data-block surface.)"""
from __future__ import annotations

import json
import re

from fastapi.testclient import TestClient


def _login(c: TestClient) -> dict[str, str]:
    r = c.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return {"ls_session": r.cookies["ls_session"]}


def _csrf(cookies: dict[str, str]) -> str:
    from app.config import get_settings
    from app.security import csrf_token
    return csrf_token(get_settings().session_secret, cookies["ls_session"])


def _create_product(c: TestClient) -> None:
    r = c.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200, r.text


def _issue_admin_set(c: TestClient, cookies: dict[str, str], url: str) -> tuple[str, str]:
    """Issue a license with an admin-set webhook URL. Returns (lid, key)."""
    r = c.post(
        "/admin/products/asm/licenses",
        data={
            "email": "x@example.com", "plan": "standard", "max_users": "10",
            "valid_days": "30", "features_json": "{}",
            "webhook_url": url,
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    loc = r.headers["location"]
    from urllib.parse import unquote
    lid = re.search(r"issued=([^&]+)", loc).group(1)
    key = unquote(re.search(r"key=([^&]+)", loc).group(1))
    return lid, key


# ----- item 2: source badge data wiring ---------------------------------


def test_licenses_data_includes_webhook_url_source(client: TestClient) -> None:
    """Admin product detail page must expose webhook_url_source on each
    license in the JSON data block so the modal JS can render a badge."""
    cookies = _login(client)
    _create_product(client)
    _issue_admin_set(client, cookies, "https://admin.example.com/wh")

    r = client.get("/admin/products/asm", cookies=cookies)
    m = re.search(
        r'<script type="application/json" id="licenses-data">\s*(\{.*?\})\s*</script>',
        r.text, re.DOTALL,
    )
    data = json.loads(m.group(1))
    assert len(data["licenses"]) == 1
    assert data["licenses"][0]["webhook_url_source"] == "admin"


# ----- item 1: convert admin -> self -----------------------------------


def test_convert_to_self_flips_source_and_rotates_secret(client: TestClient) -> None:
    cookies = _login(client)
    _create_product(client)
    lid, _ = _issue_admin_set(client, cookies, "https://admin.example.com/wh")

    # Capture the pre-convert secret directly from the DB.
    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=lid).one()
        assert lic.webhook_url_source == "admin"
        old_secret = lic.webhook_secret
        assert old_secret  # admin-set licenses ship with a secret

    r = client.post(
        f"/admin/licenses/{lid}/webhook/convert-to-self",
        data={"csrf_token": _csrf(cookies)},
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    # Redirect carries webhook_lid so the modal auto-opens + reveals secret.
    assert f"webhook_lid={lid}" in r.headers["location"]

    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=lid).one()
        assert lic.webhook_url_source == "self"
        assert lic.webhook_url == "https://admin.example.com/wh"  # unchanged
        assert lic.webhook_secret  # secret kept (rotated)
        assert lic.webhook_secret != old_secret, "secret should be rotated"


def test_convert_to_self_then_v1check_echoes_secret(client: TestClient) -> None:
    """After conversion, /v1/check must start echoing the freshly-rotated
    secret to the client (the whole point of the conversion)."""
    cookies = _login(client)
    _create_product(client)
    lid, key = _issue_admin_set(client, cookies, "https://customer.example.com/wh")

    # Pre-convert: secret NOT echoed (admin source).
    r = client.post(
        "/v1/check",
        json={"key": key, "install_id": "ii-1", "version": "1.0"},
    )
    assert r.status_code == 200
    assert r.json().get("webhook_secret") in (None, "")

    # Convert.
    client.post(
        f"/admin/licenses/{lid}/webhook/convert-to-self",
        data={"csrf_token": _csrf(cookies)},
        cookies=cookies, follow_redirects=False,
    )

    # Post-convert: secret IS echoed.
    r2 = client.post(
        "/v1/check",
        json={"key": key, "install_id": "ii-1", "version": "1.0"},
    )
    assert r2.status_code == 200
    assert r2.json().get("webhook_secret"), r2.json()


def test_convert_to_self_rejects_when_no_url(client: TestClient) -> None:
    """A license with no webhook URL has nothing to convert. Should 303 to
    the error redirect, not 500."""
    cookies = _login(client)
    _create_product(client)
    # Issue without a webhook URL.
    r = client.post(
        "/admin/products/asm/licenses",
        data={
            "email": "x@example.com", "plan": "standard", "max_users": "10",
            "valid_days": "30", "features_json": "{}",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    lid = re.search(r"issued=([^&]+)", r.headers["location"]).group(1)

    r2 = client.post(
        f"/admin/licenses/{lid}/webhook/convert-to-self",
        data={"csrf_token": _csrf(cookies)},
        cookies=cookies, follow_redirects=False,
    )
    assert r2.status_code == 303
    assert "error=" in r2.headers["location"]


def test_convert_to_self_rejects_when_already_self(client: TestClient) -> None:
    """Re-convert is a no-op + error; the button should never show in this
    state, but the endpoint must defend against repeat clicks."""
    cookies = _login(client)
    _create_product(client)
    # Issue without a URL, then self-register via /v1/check.
    r = client.post(
        "/admin/products/asm/licenses",
        data={
            "email": "x@example.com", "plan": "standard", "max_users": "10",
            "valid_days": "30", "features_json": "{}",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    from urllib.parse import unquote
    loc = r.headers["location"]
    lid = re.search(r"issued=([^&]+)", loc).group(1)
    key = unquote(re.search(r"key=([^&]+)", loc).group(1))

    client.post(
        "/v1/check",
        json={
            "key": key, "install_id": "ii-1", "version": "1.0",
            "public_url": "https://customer.example.com/wh",
        },
    )

    r2 = client.post(
        f"/admin/licenses/{lid}/webhook/convert-to-self",
        data={"csrf_token": _csrf(cookies)},
        cookies=cookies, follow_redirects=False,
    )
    assert r2.status_code == 303
    assert "error=" in r2.headers["location"]
