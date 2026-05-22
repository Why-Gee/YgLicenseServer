"""TOTP-based MFA on admin login. Tests cover the full enrolment + login flow."""
from __future__ import annotations

import re

import pyotp
from fastapi.testclient import TestClient


def _login(c: TestClient) -> dict[str, str]:
    r = c.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return {"ls_session": r.cookies["ls_session"]}


def _csrf(cookies: dict[str, str]) -> str:
    from app.config import get_settings
    from app.security import csrf_token
    return csrf_token(get_settings().session_secret, cookies["ls_session"])


def _post(c: TestClient, url: str, cookies: dict[str, str], data: dict | None = None, **kw):
    payload = dict(data or {})
    payload.setdefault("csrf_token", _csrf(cookies))
    return c.post(url, data=payload, cookies=cookies, **kw)


# ---------- enrol flow -----------------------------------------------------


def test_mfa_settings_page_renders_when_logged_in(client):
    cookies = _login(client)
    r = client.get("/admin/mfa", cookies=cookies, follow_redirects=False)
    assert r.status_code == 200, r.text
    assert b"MFA" in r.content or b"mfa" in r.content.lower()


def test_mfa_enrol_returns_provisioning_uri(client):
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies, follow_redirects=False)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["provisioning_uri"].startswith("otpauth://totp/"), body
    assert body["secret"] and re.match(r"^[A-Z2-7]+$", body["secret"]), body
    # not enabled yet — must verify with one OTP first
    from app.db import SessionLocal
    from app.models import AdminMfa
    with SessionLocal() as s:
        row = s.query(AdminMfa).first()
        assert row is not None and not row.enabled, row


def test_mfa_verify_enrol_with_valid_code_enables_and_returns_recovery_codes(client):
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    otp = pyotp.TOTP(secret).now()
    r = _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": otp})
    assert r.status_code == 200, r.text
    body = r.json()
    codes = body["recovery_codes"]
    assert len(codes) == 10
    assert all(isinstance(c, str) and len(c) >= 8 for c in codes)
    # row now enabled
    from app.db import SessionLocal
    from app.models import AdminMfa
    with SessionLocal() as s:
        row = s.query(AdminMfa).first()
        assert row.enabled


def test_mfa_verify_enrol_with_wrong_code_rejected(client):
    cookies = _login(client)
    _post(client, "/admin/mfa/enroll", cookies)
    r = _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": "000000"})
    assert r.status_code == 400, r.text
    from app.db import SessionLocal
    from app.models import AdminMfa
    with SessionLocal() as s:
        row = s.query(AdminMfa).first()
        assert not row.enabled


# ---------- disable -------------------------------------------------------


def test_mfa_disable_with_valid_otp(client):
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    # now disable
    r = _post(client, "/admin/mfa/disable", cookies, data={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    from app.db import SessionLocal
    from app.models import AdminMfa
    with SessionLocal() as s:
        row = s.query(AdminMfa).first()
        assert not row.enabled


def test_mfa_disable_with_recovery_code(client):
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    enrol = _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    rcodes = enrol.json()["recovery_codes"]
    # Disable via recovery code (no OTP needed)
    r = _post(client, "/admin/mfa/disable", cookies, data={"code": rcodes[0]})
    assert r.status_code == 200, r.text


def test_mfa_disable_with_wrong_code_rejected(client):
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    r = _post(client, "/admin/mfa/disable", cookies, data={"code": "999999"})
    assert r.status_code == 400, r.text


# ---------- recovery codes invalidation ------------------------------------


def test_recovery_code_disable_wipes_all_state(client):
    """Disabling via a recovery code wipes the row's secret + ALL stored
    recovery hashes — the remaining codes from the same set are invalid
    too. (Login-flow single-use is exercised separately in Task 5 tests.)"""
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    enrol = _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    rcodes = enrol.json()["recovery_codes"]
    r = _post(client, "/admin/mfa/disable", cookies, data={"code": rcodes[0]})
    assert r.status_code == 200
    from app.db import SessionLocal
    from app.models import AdminMfa
    with SessionLocal() as s:
        row = s.query(AdminMfa).first()
        assert row.enabled == 0
        assert row.secret_encrypted is None
        assert row.recovery_codes_hashed is None
