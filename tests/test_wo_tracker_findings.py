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


def _valid_until_str(lid: str) -> str:
    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        return s.query(License).filter_by(id=lid).one().valid_until.strftime("%Y-%m-%dT%H:%M")


def test_edit_preserves_self_source_when_url_unchanged(client: TestClient) -> None:
    """Regression: a plain license edit (changing plan/max_users/features) must
    NOT relabel a self-registered webhook as admin-source. The edit modal's form
    always carries the existing webhook_url, and edit_license used to re-apply it
    with source='admin' on every save -- silently re-locking the channel and
    killing /v1/check secret echo. This is exactly what reverted raanana after a
    Convert-to-self."""
    cookies = _login(client)
    _create_product(client)
    lid, _ = _issue_admin_set(client, cookies, "https://customer.example.com/wh")
    # Make it self-source (the state we must preserve across edits).
    client.post(
        f"/admin/licenses/{lid}/webhook/convert-to-self",
        data={"csrf_token": _csrf(cookies)}, cookies=cookies, follow_redirects=False,
    )

    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=lid).one()
        assert lic.webhook_url_source == "self"
        secret_before = lic.webhook_secret
        url_before = lic.webhook_url

    # Plain edit: bump max_users, resend the SAME webhook_url (as the modal does),
    # no rotate.
    r = client.post(
        f"/admin/licenses/{lid}/edit",
        data={
            "plan": "standard", "max_users": "42",
            "valid_until": _valid_until_str(lid), "features_json": "{}",
            "webhook_url": url_before,
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text

    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=lid).one()
        assert lic.max_users == 42, "edit must still apply"
        assert lic.webhook_url_source == "self", "self-source must survive a plain edit"
        assert lic.webhook_url == url_before, "url unchanged"
        assert lic.webhook_secret == secret_before, "secret must not rotate on a no-op webhook"


def test_edit_heals_missing_secret_without_relabeling_source(client: TestClient) -> None:
    """A self-source row that lost its secret (dead channel) must get one minted
    on a plain edit -- preserving the pre-fix heal behavior -- WITHOUT flipping
    the source back to admin."""
    cookies = _login(client)
    _create_product(client)
    lid, _ = _issue_admin_set(client, cookies, "https://customer.example.com/wh")
    client.post(
        f"/admin/licenses/{lid}/webhook/convert-to-self",
        data={"csrf_token": _csrf(cookies)}, cookies=cookies, follow_redirects=False,
    )

    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=lid).one()
        lic.webhook_secret = None  # force the dead-channel state
        s.commit()
        url_before = lic.webhook_url

    r = client.post(
        f"/admin/licenses/{lid}/edit",
        data={
            "plan": "standard", "max_users": "7",
            "valid_until": _valid_until_str(lid), "features_json": "{}",
            "webhook_url": url_before,
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text

    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=lid).one()
        assert lic.webhook_secret, "missing secret must be healed on edit"
        assert lic.webhook_url_source == "self", "heal must not relabel source to admin"


def test_edit_changing_url_sets_admin_source(client: TestClient) -> None:
    """Intended behaviour preserved: if the admin actually changes the webhook
    URL via the edit form, they're now managing it -> source flips to admin."""
    cookies = _login(client)
    _create_product(client)
    lid, _ = _issue_admin_set(client, cookies, "https://customer.example.com/wh")
    client.post(
        f"/admin/licenses/{lid}/webhook/convert-to-self",
        data={"csrf_token": _csrf(cookies)}, cookies=cookies, follow_redirects=False,
    )

    r = client.post(
        f"/admin/licenses/{lid}/edit",
        data={
            "plan": "standard", "max_users": "10",
            "valid_until": _valid_until_str(lid), "features_json": "{}",
            "webhook_url": "https://new-admin.example.com/wh",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text

    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=lid).one()
        assert lic.webhook_url == "https://new-admin.example.com/wh"
        assert lic.webhook_url_source == "admin", "admin set a new URL via the edit form"


def test_edit_rotate_secret_preserves_self_source(client: TestClient) -> None:
    """Regression (v1.4.5): ticking 'Rotate signing secret on save' on a
    self-registered webhook must rotate the secret WITHOUT flipping source back
    to admin -- a flip would stop /v1/check echoing the freshly-rotated secret,
    so the client keeps verifying with the old one and every delivery fails."""
    cookies = _login(client)
    _create_product(client)
    lid, _ = _issue_admin_set(client, cookies, "https://customer.example.com/wh")
    client.post(
        f"/admin/licenses/{lid}/webhook/convert-to-self",
        data={"csrf_token": _csrf(cookies)}, cookies=cookies, follow_redirects=False,
    )

    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=lid).one()
        assert lic.webhook_url_source == "self"
        secret_before = lic.webhook_secret
        url_before = lic.webhook_url

    r = client.post(
        f"/admin/licenses/{lid}/edit",
        data={
            "plan": "standard", "max_users": "10",
            "valid_until": _valid_until_str(lid), "features_json": "{}",
            "webhook_url": url_before, "rotate_secret": "1",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text

    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=lid).one()
        assert lic.webhook_url_source == "self", "rotate must not relabel self->admin"
        assert lic.webhook_secret and lic.webhook_secret != secret_before, "secret rotated"
        assert lic.webhook_url == url_before


def test_edit_rotate_secret_keeps_admin_source(client: TestClient) -> None:
    """Guard: rotating on an admin-source row (URL unchanged) still rotates and
    stays admin -- the source is preserved, not blindly forced either way."""
    cookies = _login(client)
    _create_product(client)
    lid, _ = _issue_admin_set(client, cookies, "https://admin.example.com/wh")

    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=lid).one()
        assert lic.webhook_url_source == "admin"
        secret_before = lic.webhook_secret

    r = client.post(
        f"/admin/licenses/{lid}/edit",
        data={
            "plan": "standard", "max_users": "10",
            "valid_until": _valid_until_str(lid), "features_json": "{}",
            "webhook_url": "https://admin.example.com/wh", "rotate_secret": "1",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text

    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=lid).one()
        assert lic.webhook_url_source == "admin"
        assert lic.webhook_secret != secret_before, "secret rotated"


def test_modal_card_css_scrolls_when_tall(client: TestClient) -> None:
    """Bug: a tall license modal overflowed the viewport with no scroll, so the
    Save button was clipped/unclickable. The shared .modal-card must cap its
    height and scroll its overflow."""
    cookies = _login(client)
    _create_product(client)
    r = client.get("/admin/products/asm", cookies=cookies)
    assert r.status_code == 200
    m = re.search(r"\.modal-card\s*\{[^}]*\}", r.text)
    assert m, ".modal-card CSS rule missing"
    rule = m.group(0)
    assert "max-height" in rule, ".modal-card must cap its height"
    assert "overflow-y" in rule or "overflow:" in rule, ".modal-card must scroll overflow"


def test_edit_unticking_allow_http_revokes_flag(client: TestClient) -> None:
    """Regression (v1.4.6): un-ticking 'Allow plain http' on the edit modal and
    saving must clear allow_http_webhook. An unchecked HTML checkbox is omitted
    from the POST; the edit route previously mapped that absence to None
    ('preserve'), silently dropping the OFF direction. The route now treats any
    value that isn't '1' (including absence) as explicit OFF.

    Uses an https URL carrying a *stale* allow_http=1 flag: that is the row a
    user legitimately wants to clear. (Clearing the flag on an http:// row
    instead fails fast by design -- you can't keep an http URL with http
    disabled -- so it can't demonstrate the clear path; see the companion test.)
    """
    cookies = _login(client)
    _create_product(client)
    lid = _issue_with_http_flag(client, cookies, "https://customer.example.com/wh")

    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=lid).one()
        assert lic.allow_http_webhook == 1, "stale flag set at issue"
        url_before = lic.webhook_url

    # Plain edit: URL unchanged, no rotate, checkbox UNCHECKED. Omit the field
    # to mimic the unchecked box (the bug) and prove the route reads absence
    # as OFF.
    r = client.post(
        f"/admin/licenses/{lid}/edit",
        data={
            "plan": "standard", "max_users": "10",
            "valid_until": _valid_until_str(lid), "features_json": "{}",
            "webhook_url": url_before,
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text

    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=lid).one()
        assert lic.allow_http_webhook == 0, "un-ticking must revoke http permission"
        assert lic.webhook_url == url_before, "URL untouched by a plain edit"


def test_edit_ticking_allow_http_sets_flag_via_companion(client: TestClient) -> None:
    """Guard the ON direction: a *checked* box posts the hidden companion's "0"
    AND the checkbox's "1" (in that order). The route must read it as True --
    i.e. the last value wins -- otherwise adding the hidden companion would
    silently break turning the flag ON."""
    cookies = _login(client)
    _create_product(client)
    lid = _issue_admin_set(client, cookies, "https://customer.example.com/wh")[0]

    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=lid).one()
        assert lic.allow_http_webhook == 0  # not set at issue
        url_before = lic.webhook_url

    # Checked box == the rendered form posts both fields, hidden "0" then "1".
    r = client.post(
        f"/admin/licenses/{lid}/edit",
        data={
            "plan": "standard", "max_users": "10",
            "valid_until": _valid_until_str(lid), "features_json": "{}",
            "webhook_url": url_before,
            "allow_http_webhook": ["0", "1"],
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text

    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=lid).one()
        assert lic.allow_http_webhook == 1, "checked box (hidden '0' + '1') must set the flag"


def test_edit_modal_has_allow_http_off_companion(client: TestClient) -> None:
    """The 'Allow plain http' checkbox needs a hidden companion that posts '0',
    so an unchecked box still expresses OFF (an unchecked checkbox is omitted
    from the POST). The hidden input must PRECEDE the checkbox so that when the
    box is checked its later '1' wins the last-value-wins form parse."""
    cookies = _login(client)
    _create_product(client)
    _issue_admin_set(client, cookies, "https://admin.example.com/wh")
    html = client.get("/admin/products/asm", cookies=cookies).text
    hidden_idx = html.find('<input type="hidden" name="allow_http_webhook" value="0">')
    checkbox_idx = html.find('id="lm-allow-http"')
    assert hidden_idx != -1, "missing hidden '0' companion for allow_http_webhook"
    assert checkbox_idx != -1, "allow-http checkbox missing"
    assert hidden_idx < checkbox_idx, "hidden '0' must precede the checkbox (last value wins)"


def _issue_with_http_flag(c: TestClient, cookies: dict[str, str], url: str) -> str:
    """Issue a license carrying webhook `url` with allow_http_webhook=1. Returns lid."""
    r = c.post(
        "/admin/products/asm/licenses",
        data={
            "email": "x@example.com", "plan": "standard", "max_users": "10",
            "valid_days": "30", "features_json": "{}",
            "webhook_url": url, "allow_http_webhook": "1",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    return re.search(r"issued=([^&]+)", r.headers["location"]).group(1)


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
