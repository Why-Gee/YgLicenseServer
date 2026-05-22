"""Admin MFA enrolment + management routes.

GET  /admin/mfa                — settings page
POST /admin/mfa/enroll         — generate secret + provisioning URI
POST /admin/mfa/verify-enroll  — confirm with one OTP, enable, return recovery codes
POST /admin/mfa/disable        — accept OTP or recovery code, clear MFA state
POST /admin/mfa/regen-recovery — replace the recovery-code set (requires OTP)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy.orm import Session

from app.db import get_db
from app.routers.admin_ui._deps import require_csrf, require_login, templates
from app.services import mfa as mfa_svc

router = APIRouter()


@router.get("/admin/mfa", response_class=HTMLResponse)
def mfa_page(request: Request, db: Session = Depends(get_db)) -> Response:
    require_login(request)
    state = mfa_svc.get_state(db)
    return templates.TemplateResponse(
        request, "mfa.html",
        {"enabled": bool(state and state.enabled)},
    )


@router.post("/admin/mfa/enroll")
def mfa_enroll(
    request: Request, csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    start = mfa_svc.start_enrol(db)
    return JSONResponse({
        "secret": start.secret,
        "provisioning_uri": start.provisioning_uri,
        "qr_svg": start.qr_svg,
    })


@router.post("/admin/mfa/verify-enroll")
def mfa_verify_enroll(
    request: Request, code: str = Form(...), csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    codes = mfa_svc.verify_enrol(db, code)
    if codes is None:
        return JSONResponse({"error": "invalid code"}, status_code=400)
    return JSONResponse({"recovery_codes": codes})


@router.post("/admin/mfa/disable")
def mfa_disable(
    request: Request, code: str = Form(...), csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    if not mfa_svc.disable(db, code):
        return JSONResponse({"error": "invalid code"}, status_code=400)
    return JSONResponse({"ok": True})


@router.post("/admin/mfa/regen-recovery")
def mfa_regen_recovery(
    request: Request, code: str = Form(...), csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    codes = mfa_svc.regen_recovery(db, code)
    if codes is None:
        return JSONResponse({"error": "invalid code"}, status_code=400)
    return JSONResponse({"recovery_codes": codes})
