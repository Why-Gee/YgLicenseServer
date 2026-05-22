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


# ---------- regen recovery codes -------------------------------------------


def test_mfa_regen_recovery_returns_fresh_codes(client):
    """regen-recovery with a valid OTP returns 10 fresh recovery codes
    and invalidates the old ones."""
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    enrol = _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    old_codes = enrol.json()["recovery_codes"]

    r = _post(client, "/admin/mfa/regen-recovery", cookies, data={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    new_codes = r.json()["recovery_codes"]
    assert len(new_codes) == 10
    assert set(new_codes).isdisjoint(set(old_codes)), "regen should produce disjoint set"

    # Old codes must no longer authenticate.
    from app.db import SessionLocal
    from app.services import mfa as mfa_svc
    with SessionLocal() as s:
        assert mfa_svc.verify_login(s, old_codes[0]) is False, "old recovery code still valid after regen"
        # And a fresh one IS valid.
        assert mfa_svc.verify_login(s, new_codes[0]) is True


def test_mfa_regen_recovery_rejects_wrong_otp(client):
    """regen-recovery with a bad OTP returns 400 and leaves recovery codes intact."""
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    enrol = _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    old_codes = enrol.json()["recovery_codes"]

    r = _post(client, "/admin/mfa/regen-recovery", cookies, data={"code": "000000"})
    assert r.status_code == 400, r.text

    # Old codes still valid.
    from app.db import SessionLocal
    from app.services import mfa as mfa_svc
    with SessionLocal() as s:
        assert mfa_svc.verify_login(s, old_codes[0]) is True


# ---------- login flow integration -----------------------------------------


def test_login_without_mfa_works_as_before(client):
    """With no MFA row (or enabled=False), POST /admin/login lands at /admin."""
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/admin"


def test_login_with_mfa_enabled_redirects_to_mfa_step(client):
    """When admin_mfa.enabled=True, POST /admin/login lands at /admin/login/mfa
    with a pre-mfa cookie (NOT the full session cookie yet)."""
    # First: enrol + enable MFA.
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    # Now log out and log back in.
    client.cookies.clear()
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    assert r.headers["location"] == "/admin/login/mfa"
    assert "ls_pre_mfa" in r.cookies
    assert "ls_session" not in r.cookies


def test_login_mfa_step_completes_with_valid_otp(client):
    """The MFA-step POST swaps the pre-mfa cookie for a full session cookie."""
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    client.cookies.clear()
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    pre_cookie = {"ls_pre_mfa": r.cookies["ls_pre_mfa"]}
    code = pyotp.TOTP(secret).now()
    r = client.post(
        "/admin/login/mfa",
        data={"code": code},
        cookies=pre_cookie, follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    assert r.headers["location"] == "/admin"
    assert "ls_session" in r.cookies


def test_login_mfa_step_rejects_bad_code(client):
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    client.cookies.clear()
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    pre_cookie = {"ls_pre_mfa": r.cookies["ls_pre_mfa"]}
    r = client.post(
        "/admin/login/mfa", data={"code": "000000"},
        cookies=pre_cookie, follow_redirects=False,
    )
    # Stays on the MFA step with an error flag.
    assert r.status_code == 303
    assert r.headers["location"].startswith("/admin/login/mfa")


def test_pre_mfa_cookie_alone_cannot_access_admin(client):
    """A user who only holds the pre-MFA cookie must not be able to reach
    any /admin/* page. The bootstrap-bypass property is structurally
    enforced (logged_in() reads only SESSION_COOKIE), but a future change
    to require_login or logged_in could silently break it — this test
    catches the regression."""
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    client.cookies.clear()
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    pre_cookie = {"ls_pre_mfa": r.cookies["ls_pre_mfa"]}
    r = client.get("/admin", cookies=pre_cookie, follow_redirects=False)
    assert r.status_code == 303
    assert "/admin/login" in r.headers["location"]


def test_logout_deletes_pre_mfa_cookie(client):
    """Logout must clear the pre-MFA cookie too. Otherwise a stale
    cookie could sit on the client for up to 5 minutes after explicit
    logout."""
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    # Log out via the (still session-authed) admin and confirm the
    # response clears BOTH cookies.
    r = _post(client, "/admin/logout", cookies, follow_redirects=False)
    assert r.status_code == 303
    set_cookie_headers = r.headers.get_list("set-cookie")
    assert any("ls_session" in h and "Max-Age=0" in h for h in set_cookie_headers), set_cookie_headers
    assert any("ls_pre_mfa" in h and "Max-Age=0" in h for h in set_cookie_headers), set_cookie_headers
