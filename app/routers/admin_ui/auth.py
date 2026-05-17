"""Login / logout + root redirect."""
from __future__ import annotations

import secrets
import time

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from app.config import Settings, get_settings
from app.rate_limit import limiter
from app.routers.admin_ui._deps import (
    SESSION_COOKIE,
    SESSION_MAX_AGE_SECONDS,
    require_csrf,
    serializer,
    templates,
)

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
) -> Response:
    if not s.admin_token:
        raise HTTPException(status_code=503, detail="ADMIN_TOKEN not set")
    if not secrets.compare_digest(token, s.admin_token):
        return RedirectResponse("/admin/login?error=invalid", status_code=303)
    cookie = serializer().dumps({"ok": True, "iat": int(time.time())})
    resp = RedirectResponse("/admin", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE, cookie,
        httponly=True, secure=s.cookie_secure, samesite="lax",
        max_age=SESSION_MAX_AGE_SECONDS,
    )
    return resp


@router.post("/admin/logout")
def logout(request: Request, csrf_token: str = Form("")) -> Response:
    require_csrf(request, csrf_token)
    resp = RedirectResponse("/admin/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp
