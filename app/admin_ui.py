"""Server-rendered admin UI.

Login uses the admin token as a password (single-user). Session cookie is
HMAC-signed (itsdangerous). Pages render via Jinja2 templates.
Form submissions go to /admin/* routes here, which call the same domain
logic as /v1/admin/* — kept in api.py for the JSON consumers.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeSerializer
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import Customer, Event, License, Product
from app.signing import generate_keypair

router = APIRouter()
TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

SESSION_COOKIE = "asm_ls_session"


def _serializer() -> URLSafeSerializer:
    s = get_settings()
    if not s.session_secret:
        raise HTTPException(status_code=503, detail="SESSION_SECRET not set")
    return URLSafeSerializer(s.session_secret, salt="admin-session")


def _logged_in(request: Request) -> bool:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return False
    try:
        _serializer().loads(raw)
        return True
    except BadSignature:
        return False


def _require_login(request: Request) -> None:
    if not _logged_in(request):
        raise HTTPException(status_code=303, headers={"location": "/admin/login"})


# ----- login flow --------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
def root(request: Request) -> Response:
    return RedirectResponse("/admin", status_code=303)


@router.get("/admin/login", response_class=HTMLResponse)
def login_form(request: Request, error: str | None = None) -> Response:
    return templates.TemplateResponse(
        "login.html", {"request": request, "error": error}
    )


@router.post("/admin/login")
def login(request: Request, token: str = Form(...)) -> Response:
    s = get_settings()
    if not s.admin_token:
        raise HTTPException(status_code=503, detail="ADMIN_TOKEN not set")
    if not secrets.compare_digest(token, s.admin_token):
        return RedirectResponse("/admin/login?error=invalid", status_code=303)
    cookie = _serializer().dumps({"ok": True})
    resp = RedirectResponse("/admin", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE, cookie,
        httponly=True, secure=s.cookie_secure, samesite="lax",
        max_age=60 * 60 * 24 * 7,  # 7 days
    )
    return resp


@router.post("/admin/logout")
def logout() -> Response:
    resp = RedirectResponse("/admin/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# ----- dashboard ---------------------------------------------------------

@router.get("/admin", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)) -> Response:
    _require_login(request)
    products = db.query(Product).order_by(Product.created_at.desc()).all()
    total_licenses = db.query(License).count()
    active_licenses = db.query(License).filter_by(status="active").count()
    recent_events = (
        db.query(Event).order_by(Event.created_at.desc()).limit(20).all()
    )
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "products": products,
            "total_licenses": total_licenses,
            "active_licenses": active_licenses,
            "recent_events": recent_events,
        },
    )


# ----- products ----------------------------------------------------------

@router.get("/admin/products/new", response_class=HTMLResponse)
def product_new_form(request: Request) -> Response:
    _require_login(request)
    return templates.TemplateResponse("product_new.html", {"request": request})


@router.post("/admin/products")
def product_create(
    request: Request,
    slug: str = Form(...),
    name: str = Form(...),
    key_prefix: str = Form(...),
    description: str = Form(""),
    jwt_issuer: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    _require_login(request)
    if db.query(Product).filter_by(slug=slug).one_or_none():
        return RedirectResponse(
            "/admin/products/new?error=slug+exists", status_code=303
        )
    priv_pem, pub_pem = generate_keypair()
    p = Product(
        slug=slug,
        name=name,
        description=description or None,
        public_key_pem=pub_pem,
        private_key_pem=priv_pem,
        key_prefix=key_prefix,
        jwt_issuer=jwt_issuer or f"{slug}-license-server",
    )
    db.add(p)
    db.add(Event(product_id=p.id, type="product:created", payload={"slug": slug}))
    db.commit()
    return RedirectResponse(f"/admin/products/{slug}", status_code=303)


@router.get("/admin/products/{slug}", response_class=HTMLResponse)
def product_detail(slug: str, request: Request, db: Session = Depends(get_db)) -> Response:
    _require_login(request)
    p = db.query(Product).filter_by(slug=slug).one_or_none()
    if p is None:
        raise HTTPException(status_code=404)
    licenses = (
        db.query(License)
        .filter_by(product_id=p.id)
        .order_by(License.created_at.desc())
        .limit(200)
        .all()
    )
    return templates.TemplateResponse(
        "product_detail.html",
        {"request": request, "product": p, "licenses": licenses},
    )


@router.get("/admin/products/{slug}/pubkey.pem", response_class=PlainTextResponse)
def product_pubkey_download(
    slug: str, request: Request, db: Session = Depends(get_db)
) -> Response:
    _require_login(request)
    p = db.query(Product).filter_by(slug=slug).one_or_none()
    if p is None:
        raise HTTPException(status_code=404)
    return PlainTextResponse(
        p.public_key_pem,
        headers={"Content-Disposition": f'attachment; filename="{slug}_pub.pem"'},
    )


# ----- licenses ----------------------------------------------------------

@router.post("/admin/products/{slug}/licenses")
def license_issue(
    slug: str,
    request: Request,
    email: str = Form(...),
    plan: str = Form("standard"),
    max_users: int = Form(10),
    valid_days: int = Form(365),
    features_json: str = Form("{}"),
    db: Session = Depends(get_db),
) -> Response:
    _require_login(request)
    import json
    p = db.query(Product).filter_by(slug=slug).one_or_none()
    if p is None:
        raise HTTPException(status_code=404)
    try:
        features = json.loads(features_json) if features_json.strip() else {}
        if not isinstance(features, dict):
            raise ValueError
    except (ValueError, json.JSONDecodeError):
        return RedirectResponse(
            f"/admin/products/{slug}?error=invalid+features+json", status_code=303
        )

    cust = db.query(Customer).filter_by(email=email).one_or_none()
    if cust is None:
        cust = Customer(email=email)
        db.add(cust)
        db.flush()
    key = f"{p.key_prefix}_" + secrets.token_urlsafe(32)
    lic = License(
        product_id=p.id,
        customer_id=cust.id,
        key=key,
        plan=plan,
        max_users=max_users,
        features=features,
        valid_until=datetime.utcnow() + timedelta(days=valid_days),
        status="active",
    )
    db.add(lic)
    db.add(Event(
        license_id=lic.id, product_id=p.id, type="issued",
        payload={"plan": plan}, note="ui/issue",
    ))
    db.commit()
    return RedirectResponse(
        f"/admin/products/{slug}?issued={lic.id}", status_code=303
    )


@router.post("/admin/licenses/{lid}/revoke")
def license_revoke(lid: str, request: Request, db: Session = Depends(get_db)) -> Response:
    _require_login(request)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    lic.status = "revoked"
    db.add(Event(
        license_id=lic.id, product_id=lic.product_id, type="status:revoked",
        note="ui/revoke",
    ))
    db.commit()
    return RedirectResponse(f"/admin/products/{lic.product.slug}", status_code=303)


# ----- customers / events --------------------------------------------------

@router.get("/admin/customers", response_class=HTMLResponse)
def customers_list(request: Request, db: Session = Depends(get_db)) -> Response:
    _require_login(request)
    rows = db.query(Customer).order_by(Customer.created_at.desc()).all()
    return templates.TemplateResponse(
        "customers.html", {"request": request, "customers": rows}
    )


@router.get("/admin/events", response_class=HTMLResponse)
def events_list(request: Request, db: Session = Depends(get_db)) -> Response:
    _require_login(request)
    rows = db.query(Event).order_by(Event.created_at.desc()).limit(500).all()
    return templates.TemplateResponse(
        "events.html", {"request": request, "events": rows}
    )
