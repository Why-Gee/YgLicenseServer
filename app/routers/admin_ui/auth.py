"""Login / logout + root redirect."""
from __future__ import annotations

import secrets
import time

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import get_db
from app.rate_limit import limiter
from app.routers.admin_ui._deps import (
    PRE_MFA_COOKIE,
    PRE_MFA_MAX_AGE_SECONDS,
    SESSION_COOKIE,
    SESSION_MAX_AGE_SECONDS,
    pre_mfa_serializer,
    pre_mfa_valid,
    require_csrf,
    serializer,
    templates,
)
from app.services import mfa as mfa_svc

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def root(request: Request) -> Response:
    return RedirectResponse("/admin", status_code=303)


@router.get("/admin/login", response_class=HTMLResponse)
def login_form(request: Request, error: str | None = None) -> Response:
    return templates.TemplateResponse(request, "login.html", {"error": error})


@router.post("/admin/login")
@limiter.limit("10/minute")
def login(
    request: Request,
    token: str = Form(...),
    s: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> Response:
    if not s.admin_token:
        raise HTTPException(status_code=503, detail="ADMIN_TOKEN not set")
    if not secrets.compare_digest(token, s.admin_token):
        return RedirectResponse("/admin/login?error=invalid", status_code=303)
    if mfa_svc.is_enabled(db):
        # First factor ok; set a short-lived pre-MFA cookie and route to
        # the second-factor entry page. The pre-MFA cookie is NOT a session
        # — it cannot access any /admin/* page except /admin/login/mfa.
        pre = pre_mfa_serializer().dumps({"ok": True, "iat": int(time.time())})
        resp = RedirectResponse("/admin/login/mfa", status_code=303)
        resp.set_cookie(
            PRE_MFA_COOKIE, pre,
            httponly=True, secure=s.cookie_secure, samesite="lax",
            max_age=PRE_MFA_MAX_AGE_SECONDS,
        )
        return resp
    # No MFA: original single-factor flow.
    cookie = serializer().dumps({"ok": True, "iat": int(time.time())})
    resp = RedirectResponse("/admin", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE, cookie,
        httponly=True, secure=s.cookie_secure, samesite="lax",
        max_age=SESSION_MAX_AGE_SECONDS,
    )
    return resp


@router.get("/admin/login/mfa", response_class=HTMLResponse)
def login_mfa_form(request: Request, error: str | None = None) -> Response:
    if not pre_mfa_valid(request):
        return RedirectResponse("/admin/login", status_code=303)
    return templates.TemplateResponse(request, "login_mfa.html", {"error": error})


@router.post("/admin/login/mfa")
@limiter.limit("10/minute")
def login_mfa(
    request: Request, code: str = Form(...),
    s: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> Response:
    if not pre_mfa_valid(request):
        return RedirectResponse("/admin/login", status_code=303)
    if not mfa_svc.verify_login(db, code):
        return RedirectResponse("/admin/login/mfa?error=invalid", status_code=303)
    # Promote pre-MFA → full session.
    cookie = serializer().dumps({"ok": True, "iat": int(time.time())})
    resp = RedirectResponse("/admin", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE, cookie,
        httponly=True, secure=s.cookie_secure, samesite="lax",
        max_age=SESSION_MAX_AGE_SECONDS,
    )
    resp.delete_cookie(PRE_MFA_COOKIE)
    return resp


@router.post("/admin/logout")
def logout(request: Request, csrf_token: str = Form("")) -> Response:
    require_csrf(request, csrf_token)
    resp = RedirectResponse("/admin/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp
