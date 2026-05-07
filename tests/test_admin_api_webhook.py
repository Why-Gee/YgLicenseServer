"""Tests for the programmatic admin webhook endpoint.

POST /admin/api/licenses/{license_id}/webhook -- bearer-auth sister of the
form-driven UI handler. Lets ASM's start.ps1 wire a fresh cloudflared quick
tunnel into the license without driving the UI.
"""
from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    db_path = tmp_path / "license.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ADMIN_TOKEN", "test-admin")
    monkeypatch.setenv("SESSION_SECRET", "test-session")
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


def _bootstrap_license(client: TestClient, *, webhook_url: str = "") -> str:
    """Create a product + issue a license via the existing admin paths.
    Returns the new license_id."""
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200, r.text
    # log in to use the form handler that issues licenses
    r = client.post(
        "/admin/login", data={"token": "test-admin"}, follow_redirects=False
    )
    cookies = {"asm_ls_session": r.cookies["asm_ls_session"]}
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
    return r.headers["location"].rsplit("issued=", 1)[1]


URL = "https://example.com/api/license/webhook"
URL2 = "https://example2.com/api/license/webhook"


def test_token_required_no_header(client) -> None:
    lid = _bootstrap_license(client)
    r = client.post(
        f"/admin/api/licenses/{lid}/webhook",
        json={"url": URL, "rotate": False},
    )
    assert r.status_code == 401, r.text


def test_token_required_bad_token(client) -> None:
    lid = _bootstrap_license(client)
    r = client.post(
        f"/admin/api/licenses/{lid}/webhook",
        headers={"Authorization": "Bearer wrong"},
        json={"url": URL, "rotate": False},
    )
    assert r.status_code == 401, r.text


def test_first_time_set_auto_mints_secret_even_without_rotate(client) -> None:
    lid = _bootstrap_license(client)  # no webhook initially
    r = client.post(
        f"/admin/api/licenses/{lid}/webhook",
        headers={"Authorization": "Bearer test-admin"},
        json={"url": URL, "rotate": False},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["webhook_url"] == URL
    assert body["webhook_secret"].startswith("whsec_")


def test_url_update_keeps_existing_secret(client) -> None:
    """rotate=False on a license that already has a secret should NOT mint."""
    lid = _bootstrap_license(client, webhook_url=URL)
    # Read the original secret by setting the same URL again.
    r1 = client.post(
        f"/admin/api/licenses/{lid}/webhook",
        headers={"Authorization": "Bearer test-admin"},
        json={"url": URL, "rotate": False},
    )
    sec1 = r1.json()["webhook_secret"]
    # Change URL with rotate=False -- secret must stay the same.
    r2 = client.post(
        f"/admin/api/licenses/{lid}/webhook",
        headers={"Authorization": "Bearer test-admin"},
        json={"url": URL2, "rotate": False},
    )
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["webhook_url"] == URL2
    assert body["webhook_secret"] == sec1


def test_rotate_true_mints_new_secret(client) -> None:
    lid = _bootstrap_license(client, webhook_url=URL)
    r1 = client.post(
        f"/admin/api/licenses/{lid}/webhook",
        headers={"Authorization": "Bearer test-admin"},
        json={"url": URL, "rotate": False},
    )
    sec1 = r1.json()["webhook_secret"]
    r2 = client.post(
        f"/admin/api/licenses/{lid}/webhook",
        headers={"Authorization": "Bearer test-admin"},
        json={"url": URL, "rotate": True},
    )
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["webhook_secret"].startswith("whsec_")
    assert body["webhook_secret"] != sec1


def test_empty_url_clears_both_fields(client) -> None:
    lid = _bootstrap_license(client, webhook_url=URL)
    r = client.post(
        f"/admin/api/licenses/{lid}/webhook",
        headers={"Authorization": "Bearer test-admin"},
        json={"url": "", "rotate": False},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["webhook_url"] is None
    assert body["webhook_secret"] is None


def test_unknown_license_returns_404(client) -> None:
    # Make sure ADMIN_TOKEN is wired so we don't get a 503.
    _bootstrap_license(client)
    r = client.post(
        "/admin/api/licenses/does-not-exist/webhook",
        headers={"Authorization": "Bearer test-admin"},
        json={"url": URL, "rotate": False},
    )
    assert r.status_code == 404, r.text


def test_missing_url_field_is_422(client) -> None:
    lid = _bootstrap_license(client)
    r = client.post(
        f"/admin/api/licenses/{lid}/webhook",
        headers={"Authorization": "Bearer test-admin"},
        json={"rotate": False},
    )
    assert r.status_code == 422, r.text


def test_wrong_type_for_rotate_is_422(client) -> None:
    lid = _bootstrap_license(client)
    r = client.post(
        f"/admin/api/licenses/{lid}/webhook",
        headers={"Authorization": "Bearer test-admin"},
        json={"url": URL, "rotate": "sometimes"},
    )
    assert r.status_code == 422, r.text
