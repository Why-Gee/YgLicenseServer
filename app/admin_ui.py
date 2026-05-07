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

from app import webhooks as wh
from app.config import get_settings
from app.db import get_db
from app.models import Customer, Event, Install, License, Product
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
        request, "login.html", {"error": error}
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
        request,
        "dashboard.html",
        {
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
    return templates.TemplateResponse(request, "product_new.html")


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


def _delete_product(db: Session, p: Product) -> int:
    """Delete a product and everything under it. Returns license count killed.

    Customers are NOT deleted (they may own licenses for other products on
    this server). Events for this product survive with product_id NULL'd
    so the audit trail still shows the historical activity.
    """
    licenses = db.query(License).filter_by(product_id=p.id).all()
    license_count = len(licenses)
    for lic in licenses:
        _delete_license(db, lic)
    db.add(Event(
        type="product:deleted",
        payload={
            "product_id": p.id, "slug": p.slug, "name": p.name,
            "license_count": license_count,
        },
        note="ui/delete",
    ))
    db.query(Event).filter_by(product_id=p.id).update({"product_id": None})
    db.delete(p)
    return license_count


@router.post("/admin/products/{slug}/delete")
def product_delete_one(slug: str, request: Request, db: Session = Depends(get_db)) -> Response:
    """Single-row delete (trash-icon path)."""
    _require_login(request)
    p = db.query(Product).filter_by(slug=slug).one_or_none()
    if p is None:
        raise HTTPException(status_code=404)
    license_count = _delete_product(db, p)
    db.commit()
    return RedirectResponse(
        f"/admin?deleted_products=1&deleted_licenses={license_count}",
        status_code=303,
    )


@router.post("/admin/products/delete")
def products_bulk_delete(
    request: Request,
    product_slugs: list[str] = Form(default=[]),
    db: Session = Depends(get_db),
) -> Response:
    _require_login(request)
    if not product_slugs:
        return RedirectResponse("/admin?error=no+products+selected", status_code=303)
    deleted_products = 0
    deleted_licenses = 0
    for slug in product_slugs:
        p = db.query(Product).filter_by(slug=slug).one_or_none()
        if p is None:
            continue
        deleted_licenses += _delete_product(db, p)
        deleted_products += 1
    db.commit()
    return RedirectResponse(
        f"/admin?deleted_products={deleted_products}&deleted_licenses={deleted_licenses}",
        status_code=303,
    )


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
        request, "product_detail.html",
        {"product": p, "licenses": licenses},
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
    webhook_url: str = Form(""),
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
    webhook_url_clean = webhook_url.strip() or None
    webhook_secret_value = wh.generate_secret() if webhook_url_clean else None
    lic = License(
        product_id=p.id,
        customer_id=cust.id,
        key=key,
        plan=plan,
        max_users=max_users,
        features=features,
        valid_until=datetime.utcnow() + timedelta(days=valid_days),
        status="active",
        webhook_url=webhook_url_clean,
        webhook_secret=webhook_secret_value,
    )
    db.add(lic)
    db.add(Event(
        license_id=lic.id, product_id=p.id, type="issued",
        payload={"plan": plan, "webhook": bool(webhook_url_clean)}, note="ui/issue",
    ))
    db.commit()
    return RedirectResponse(
        f"/admin/products/{slug}?issued={lic.id}", status_code=303
    )


@router.post("/admin/licenses/{lid}/webhook")
def license_webhook_update(
    lid: str,
    request: Request,
    webhook_url: str = Form(""),
    rotate_secret: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Set / change / clear the webhook URL on an existing license.
    `rotate_secret=1` regenerates the signing secret (use after the customer
    rotates their receiver key)."""
    _require_login(request)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    new_url = webhook_url.strip() or None
    if new_url:
        if lic.webhook_url != new_url or rotate_secret == "1" or not lic.webhook_secret:
            lic.webhook_secret = wh.generate_secret()
        lic.webhook_url = new_url
    else:
        lic.webhook_url = None
        lic.webhook_secret = None
    db.add(Event(
        license_id=lic.id, product_id=lic.product_id, type="webhook:updated",
        payload={"set": bool(new_url)}, note="ui/webhook",
    ))
    db.commit()
    return RedirectResponse(
        f"/admin/products/{lic.product.slug}?webhook_lid={lic.id}", status_code=303
    )


@router.post("/admin/licenses/{lid}/webhook/test")
def license_webhook_test(lid: str, request: Request, db: Session = Depends(get_db)) -> Response:
    """Send a synthetic license.status.changed event to the configured URL.
    Useful right after issuance to confirm the customer's receiver works."""
    _require_login(request)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    if not lic.webhook_url or not lic.webhook_secret:
        return RedirectResponse(
            f"/admin/products/{lic.product.slug}?error=no+webhook+configured",
            status_code=303,
        )
    ok, status, err = wh.deliver(
        url=lic.webhook_url, secret=lic.webhook_secret,
        event_type="license.test",
        data={
            "license_id": lic.id, "key": lic.key,
            "product_slug": lic.product.slug,
            "customer_email": lic.customer.email,
            "test": True,
        },
    )
    qs = (
        f"webhook_test_lid={lic.id}&webhook_test_ok={int(ok)}"
        f"&webhook_test_status={status or ''}"
    )
    return RedirectResponse(f"/admin/products/{lic.product.slug}?{qs}", status_code=303)


def _set_license_status(db: Session, lic: License, new_status: str, note: str) -> None:
    previous = lic.status
    lic.status = new_status
    db.add(Event(
        license_id=lic.id, product_id=lic.product_id,
        type=f"status:{new_status}", note=note,
    ))
    db.flush()  # ensure status committed in-session before webhook reads it
    # Best-effort outbound webhook. Fire-and-forget — failures are logged
    # but never raised, so a webhook outage doesn't block admin actions.
    wh.deliver_status_change(license_obj=lic, previous_status=previous)


@router.post("/admin/licenses/{lid}/revoke")
def license_revoke(lid: str, request: Request, db: Session = Depends(get_db)) -> Response:
    _require_login(request)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    _set_license_status(db, lic, "revoked", "ui/revoke")
    db.commit()
    return RedirectResponse(f"/admin/products/{lic.product.slug}", status_code=303)


@router.post("/admin/licenses/{lid}/disable")
def license_disable(lid: str, request: Request, db: Session = Depends(get_db)) -> Response:
    """Soft-toggle off. Distinct from revoke — can be flipped back via /enable.
    Same effect on /v1/check while disabled (401 reason=disabled)."""
    _require_login(request)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    _set_license_status(db, lic, "disabled", "ui/disable")
    db.commit()
    return RedirectResponse(f"/admin/products/{lic.product.slug}", status_code=303)


@router.post("/admin/licenses/{lid}/enable")
def license_enable(lid: str, request: Request, db: Session = Depends(get_db)) -> Response:
    """Flip a disabled or revoked license back to active. ASM clients drop
    upstream_rejected on the next /v1/check (every 24h via Celery beat, or
    immediately on backend restart)."""
    _require_login(request)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    _set_license_status(db, lic, "active", "ui/enable")
    db.commit()
    return RedirectResponse(f"/admin/products/{lic.product.slug}", status_code=303)


def _delete_license(db: Session, lic: License) -> None:
    # Snapshot fields BEFORE delete so we can fire the webhook with them
    # afterwards (the License row is gone and lic.product / lic.customer
    # become unreachable post-flush).
    webhook_url = lic.webhook_url
    webhook_secret = lic.webhook_secret
    snapshot = {
        "license_id": lic.id,
        "key": lic.key,
        "product_slug": lic.product.slug,
        "customer_email": lic.customer.email,
    }
    # Audit row first (with the key snapshot so a deleted-license trail still
    # tells you what was killed). Existing event rows for this license get
    # license_id NULL'd to preserve their history without a dangling FK.
    db.add(Event(
        product_id=lic.product_id, type="license:deleted",
        payload=snapshot, note="ui/delete",
    ))
    db.query(Event).filter_by(license_id=lic.id).update({"license_id": None})
    db.query(Install).filter_by(license_id=lic.id).delete()
    db.delete(lic)
    # Best-effort outbound webhook for the deletion event.
    if webhook_url and webhook_secret:
        wh.deliver_deleted(webhook_url=webhook_url, webhook_secret=webhook_secret, **snapshot)


@router.post("/admin/licenses/{lid}/delete")
def license_delete_one(lid: str, request: Request, db: Session = Depends(get_db)) -> Response:
    """Single-row delete (trash-icon path). Bulk delete on the form-level
    submit button still works for multi-select."""
    _require_login(request)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    slug = lic.product.slug
    _delete_license(db, lic)
    db.commit()
    return RedirectResponse(f"/admin/products/{slug}?deleted=1", status_code=303)


@router.post("/admin/products/{slug}/licenses/delete")
def licenses_bulk_delete(
    slug: str,
    request: Request,
    license_ids: list[str] = Form(default=[]),
    db: Session = Depends(get_db),
) -> Response:
    _require_login(request)
    p = db.query(Product).filter_by(slug=slug).one_or_none()
    if p is None:
        raise HTTPException(status_code=404)
    if not license_ids:
        return RedirectResponse(
            f"/admin/products/{slug}?error=no+licenses+selected", status_code=303
        )
    deleted = 0
    for lid in license_ids:
        lic = db.query(License).filter_by(id=lid, product_id=p.id).one_or_none()
        if lic is None:
            continue
        _delete_license(db, lic)
        deleted += 1
    db.commit()
    return RedirectResponse(
        f"/admin/products/{slug}?deleted={deleted}", status_code=303
    )


# ----- customers / events --------------------------------------------------

@router.get("/admin/customers", response_class=HTMLResponse)
def customers_list(request: Request, db: Session = Depends(get_db)) -> Response:
    _require_login(request)
    rows = db.query(Customer).order_by(Customer.created_at.desc()).all()
    return templates.TemplateResponse(
        request, "customers.html", {"customers": rows}
    )


@router.get("/admin/events", response_class=HTMLResponse)
def events_list(request: Request, db: Session = Depends(get_db)) -> Response:
    _require_login(request)
    rows = db.query(Event).order_by(Event.created_at.desc()).limit(500).all()
    return templates.TemplateResponse(
        request, "events.html", {"events": rows}
    )
