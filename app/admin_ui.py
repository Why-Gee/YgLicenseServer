"""Server-rendered admin UI.

Login uses the admin token as a password (single-user). Session cookie is
HMAC-signed (itsdangerous). Pages render via Jinja2 templates.
Form submissions go to /admin/* routes here, which call the same domain
logic as /v1/admin/* — kept in api.py for the JSON consumers.
"""
from __future__ import annotations

import logging
import secrets
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeSerializer
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import __version__
from app import webhooks as wh
from app.config import get_settings
from app.db import get_db
from app.models import Customer, Event, Install, License, Product
from app.security import check_admin_bearer, is_safe_url_shape
from app.signing import generate_keypair

log = logging.getLogger("license-server.admin")

router = APIRouter()
TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
# Make __version__ available to all templates without threading through every
# TemplateResponse context dict.
templates.env.globals["app_version"] = __version__

SESSION_COOKIE = "asm_ls_session"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 7  # 7 days


class _LoginRequired(Exception):
    """Raised by handlers when an unauthenticated visitor hits an admin page.
    Caught by an exception handler registered in app.main that returns a
    303 RedirectResponse — keeps each handler free of the redirect-return
    plumbing while emitting a real redirect (not a JSON HTTPException body).
    """


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


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
        data = _serializer().loads(raw)
    except BadSignature:
        return False
    # Reject ancient cookies even if the signature is still valid. Stolen
    # cookies become useless after SESSION_MAX_AGE_SECONDS instead of
    # surviving until SESSION_SECRET rotates (which would log everyone out).
    iat = data.get("iat") if isinstance(data, dict) else None
    if not isinstance(iat, int):
        return False
    if int(time.time()) - iat > SESSION_MAX_AGE_SECONDS:
        return False
    return True


def _require_login(request: Request) -> None:
    if not _logged_in(request):
        raise _LoginRequired()


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
    cookie = _serializer().dumps({"ok": True, "iat": int(time.time())})
    resp = RedirectResponse("/admin", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE, cookie,
        httponly=True, secure=s.cookie_secure, samesite="lax",
        max_age=SESSION_MAX_AGE_SECONDS,
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
    """Counter widgets + Recent Events. The full products list lives at
    /admin/products since v0.7.1; dashboard keeps only the top-level KPIs."""
    _require_login(request)
    product_count = db.query(Product).count()
    customer_count = db.query(Customer).count()
    total_licenses = db.query(License).count()
    active_licenses = db.query(License).filter_by(status="active").count()
    recent_events = (
        db.query(Event).order_by(Event.created_at.desc()).limit(20).all()
    )
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "product_count": product_count,
            "customer_count": customer_count,
            "total_licenses": total_licenses,
            "active_licenses": active_licenses,
            "recent_events": recent_events,
        },
    )


# ----- products ----------------------------------------------------------

@router.get("/admin/products", response_class=HTMLResponse)
def products_list(request: Request, db: Session = Depends(get_db)) -> Response:
    """Full products listing — moved out of the dashboard in v0.7.1."""
    _require_login(request)
    products = db.query(Product).order_by(Product.created_at.desc()).all()
    return templates.TemplateResponse(
        request, "products.html", {"products": products},
    )


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


def _delete_product(db: Session, p: Product, bg: BackgroundTasks | None) -> int:
    """Delete a product and everything under it. Returns license count killed.

    Customers are NOT deleted (they may own licenses for other products on
    this server). Events for this product survive with product_id NULL'd
    so the audit trail still shows the historical activity.
    """
    licenses = db.query(License).filter_by(product_id=p.id).all()
    license_count = len(licenses)
    for lic in licenses:
        _delete_license(db, lic, bg)
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
def product_delete_one(
    slug: str, request: Request, bg: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Response:
    """Single-row delete (trash-icon path)."""
    _require_login(request)
    p = db.query(Product).filter_by(slug=slug).one_or_none()
    if p is None:
        raise HTTPException(status_code=404)
    license_count = _delete_product(db, p, bg)
    db.commit()
    return RedirectResponse(
        f"/admin?deleted_products=1&deleted_licenses={license_count}",
        status_code=303,
    )


@router.post("/admin/products/delete")
def products_bulk_delete(
    request: Request,
    bg: BackgroundTasks,
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
        deleted_licenses += _delete_product(db, p, bg)
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
    customer_name: str = Form(""),
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

    name_clean = customer_name.strip() or None
    cust = db.query(Customer).filter_by(email=email).one_or_none()
    if cust is None:
        cust = Customer(email=email, name=name_clean)
        db.add(cust)
        db.flush()
    elif name_clean and cust.name != name_clean:
        # Existing customer: overwrite name when admin supplied a non-empty
        # value. Empty submission leaves the prior name alone (don't wipe by
        # accident from the issue form).
        cust.name = name_clean
    key = f"{p.key_prefix}_" + secrets.token_urlsafe(32)
    webhook_url_clean = webhook_url.strip() or None
    if webhook_url_clean and not is_safe_url_shape(webhook_url_clean, allow_http=True):
        return RedirectResponse(
            f"/admin/products/{slug}?error=unsafe+webhook+url", status_code=303
        )
    webhook_secret_value = wh.generate_secret() if webhook_url_clean else None
    lic = License(
        product_id=p.id,
        customer_id=cust.id,
        key=key,
        plan=plan,
        max_users=max_users,
        features=features,
        valid_until=_utcnow() + timedelta(days=valid_days),
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


def _apply_webhook_config(
    lic: License, *, url: str | None, rotate: bool, mint_on_url_change: bool
) -> None:
    """Mutate `lic.webhook_url` + `lic.webhook_secret` per the rotate semantics.

    Always mints a fresh secret when:
      - `rotate=True` (caller explicitly asked), OR
      - the license has no secret yet (first-time set), OR
      - `mint_on_url_change=True` and the URL actually changed.

    `mint_on_url_change=True` matches the UI handler's existing behavior:
    clicking Update with a new URL implicitly rotates the secret. The JSON
    API uses `mint_on_url_change=False` so callers control rotation.

    `url=None` clears both fields. Caller commits the session.
    """
    if url:
        should_mint = (
            rotate
            or not lic.webhook_secret
            or (mint_on_url_change and lic.webhook_url != url)
        )
        if should_mint:
            lic.webhook_secret = wh.generate_secret()
        lic.webhook_url = url
    else:
        lic.webhook_url = None
        lic.webhook_secret = None


@router.post("/admin/licenses/{lid}/edit")
def license_edit(
    lid: str,
    request: Request,
    bg: BackgroundTasks,
    plan: str = Form(...),
    max_users: int = Form(...),
    valid_until: str = Form(...),
    customer_name: str = Form(""),
    features_json: str = Form("{}"),
    webhook_url: str = Form(""),
    rotate_secret: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Edit an existing license — plan / max_users / valid_until / features
    plus the per-license webhook config. Email + key are not editable.
    Same redirect contract as /webhook update so the secret is shown once
    when set or rotated."""
    _require_login(request)
    import json
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    try:
        features = json.loads(features_json) if features_json.strip() else {}
        if not isinstance(features, dict):
            raise ValueError
    except (ValueError, json.JSONDecodeError):
        return RedirectResponse(
            f"/admin/products/{lic.product.slug}?error=invalid+features+json",
            status_code=303,
        )
    try:
        # HTML <input type="date"> posts YYYY-MM-DD. datetime-local would post
        # YYYY-MM-DDTHH:MM. Accept either.
        if "T" in valid_until:
            new_valid_until = datetime.fromisoformat(valid_until)
        else:
            new_valid_until = datetime.strptime(valid_until, "%Y-%m-%d")
    except ValueError:
        return RedirectResponse(
            f"/admin/products/{lic.product.slug}?error=invalid+valid_until",
            status_code=303,
        )
    # Diff before mutating so we can fire a `license.updated` webhook for any
    # meaningful change. Status changes have their own event and aren't
    # reachable from this form (edit modal only edits plan/etc).
    changed: list[str] = []
    if lic.plan != plan:
        changed.append("plan")
    if lic.max_users != max_users:
        changed.append("max_users")
    if lic.valid_until != new_valid_until:
        changed.append("valid_until")
    if (lic.features or {}) != features:
        changed.append("features")
    lic.plan = plan
    lic.max_users = max_users
    lic.valid_until = new_valid_until
    lic.features = features
    # Customer name is editable from this modal -- empty value clears it,
    # non-empty overwrites. Email + key remain immutable.
    if (lic.customer.name or None) != (customer_name.strip() or None):
        changed.append("customer_name")
    lic.customer.name = customer_name.strip() or None
    new_url = webhook_url.strip() or None
    if new_url and not is_safe_url_shape(new_url, allow_http=True):
        return RedirectResponse(
            f"/admin/products/{lic.product.slug}?error=unsafe+webhook+url",
            status_code=303,
        )
    # Single source of truth -- same helper the dedicated /webhook handler
    # and the JSON API path call. mint_on_url_change=True preserves the
    # form-handler convention that changing the URL implicitly rotates.
    # First-time set (no prior secret) auto-mints regardless of rotate.
    prev_secret = lic.webhook_secret
    _apply_webhook_config(
        lic, url=new_url, rotate=rotate_secret == "1", mint_on_url_change=True
    )
    secret_changed = lic.webhook_secret != prev_secret
    db.add(Event(
        license_id=lic.id, product_id=lic.product_id, type="license:edited",
        payload={"webhook": bool(new_url), "secret_changed": secret_changed},
        note="ui/edit",
    ))
    db.commit()
    # Push a `license.updated` event so receivers (e.g. ASM) refresh their
    # cached JWT without waiting for the next phone-home interval. Dispatched
    # via BackgroundTasks so a slow receiver doesn't pin the admin save.
    if changed and lic.webhook_url and lic.webhook_secret:
        data = {
            "license_id": lic.id,
            "license_key": lic.key,
            "key": lic.key,
            "product_slug": lic.product.slug if lic.product else None,
            "customer_email": lic.customer.email if lic.customer else None,
            "status": lic.status,
            "changed_fields": list(changed),
        }
        bg.add_task(
            wh.deliver,
            url=lic.webhook_url, secret=lic.webhook_secret,
            event_type=wh.EVENT_UPDATED, data=data,
        )
    # webhook_lid query param triggers the modal to auto-open with the secret
    # pre revealed when one was set/rotated; otherwise just `edited` so the
    # banner shows but the modal stays closed.
    qp = "webhook_lid" if secret_changed and new_url else "edited"
    return RedirectResponse(
        f"/admin/products/{lic.product.slug}?{qp}={lic.id}", status_code=303
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
    if new_url and not is_safe_url_shape(new_url, allow_http=True):
        return RedirectResponse(
            f"/admin/products/{lic.product.slug}?error=unsafe+webhook+url",
            status_code=303,
        )
    _apply_webhook_config(
        lic, url=new_url, rotate=rotate_secret == "1", mint_on_url_change=True
    )
    db.add(Event(
        license_id=lic.id, product_id=lic.product_id, type="webhook:updated",
        payload={"set": bool(new_url)}, note="ui/webhook",
    ))
    db.commit()
    return RedirectResponse(
        f"/admin/products/{lic.product.slug}?webhook_lid={lic.id}", status_code=303
    )


# ----- programmatic admin API (Bearer ADMIN_TOKEN) -----------------------
# Bearer-token sister of the form-driven /admin/licenses/{lid}/webhook
# above. Lets external scripts (e.g. ASM's start.ps1 spinning up a fresh
# cloudflared quick tunnel on each boot) wire the receiver URL + read back
# the signing secret without driving the admin UI.

class _WebhookConfigIn(BaseModel):
    url: str  # required; empty string clears (delete url + secret)
    rotate: bool = False


class _WebhookConfigOut(BaseModel):
    webhook_url: str | None
    webhook_secret: str | None


def _require_admin_bearer(authorization: str | None) -> None:
    s = get_settings()
    if not s.admin_token:
        raise HTTPException(status_code=503, detail="admin disabled (ADMIN_TOKEN unset)")
    if not check_admin_bearer(authorization, s.admin_token):
        raise HTTPException(status_code=401, detail="invalid admin token")


@router.post(
    "/admin/api/licenses/{license_id}/webhook",
    response_model=_WebhookConfigOut,
)
def admin_api_webhook_set(
    license_id: str,
    body: _WebhookConfigIn,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> _WebhookConfigOut:
    """Programmatic admin endpoint -- mirrors the UI form handler above but
    with bearer auth, JSON I/O, and explicit rotate semantics. The current
    secret is always returned (even when not minted this call) so the
    caller can populate a fresh receiver env file on every boot."""
    _require_admin_bearer(authorization)
    lic = db.query(License).filter_by(id=license_id).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404, detail="license not found")
    new_url = body.url.strip() or None
    if new_url and not is_safe_url_shape(new_url, allow_http=True):
        raise HTTPException(status_code=400, detail="unsafe webhook url")
    _apply_webhook_config(
        lic, url=new_url, rotate=body.rotate, mint_on_url_change=False
    )
    db.add(Event(
        license_id=lic.id, product_id=lic.product_id, type="webhook:updated",
        payload={"set": bool(new_url), "rotated": body.rotate},
        note="api/webhook",
    ))
    db.commit()
    return _WebhookConfigOut(
        webhook_url=lic.webhook_url, webhook_secret=lic.webhook_secret
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


def _webhook_snapshot(lic: License) -> dict:
    """Snapshot just the fields a status-change webhook needs, so the
    BackgroundTask doesn't try to dereference an ORM-detached row."""
    return {
        "url": lic.webhook_url,
        "secret": lic.webhook_secret,
        "license_id": lic.id,
        "license_key": lic.key,
        "product_slug": lic.product.slug if lic.product else None,
        "customer_email": lic.customer.email if lic.customer else None,
        "status": lic.status,
    }


def _deliver_status_change_async(snapshot: dict, previous_status: str) -> None:
    """BackgroundTask body. Re-builds the deliver() call from the snapshot
    so we don't touch the ORM session from the task thread."""
    if not snapshot["url"] or not snapshot["secret"]:
        return
    data = {
        "license_id": snapshot["license_id"],
        "license_key": snapshot["license_key"],
        "key": snapshot["license_key"],
        "product_slug": snapshot["product_slug"],
        "customer_email": snapshot["customer_email"],
        "previous_status": previous_status,
        "current_status": snapshot["status"],
    }
    wh.deliver(
        url=snapshot["url"], secret=snapshot["secret"],
        event_type=wh.EVENT_STATUS_CHANGED, data=data,
    )


def _set_license_status(
    db: Session, lic: License, new_status: str, note: str,
    bg: BackgroundTasks | None,
) -> None:
    previous = lic.status
    lic.status = new_status
    db.add(Event(
        license_id=lic.id, product_id=lic.product_id,
        type=f"status:{new_status}", note=note,
    ))
    # COMMIT before scheduling the webhook. Receivers POST back into
    # /v1/check synchronously from inside their handler; they must see the
    # committed status, not a flush-only-in-session preview.
    db.commit()
    # Snapshot AFTER commit (status is now persisted). The BackgroundTask
    # runs after the response is sent so a slow receiver no longer pins the
    # admin handler thread -- bulk operations don't fan out into N*5s waits.
    snapshot = _webhook_snapshot(lic)
    if bg is not None:
        bg.add_task(_deliver_status_change_async, snapshot, previous)
    else:
        _deliver_status_change_async(snapshot, previous)


@router.post("/admin/licenses/{lid}/revoke")
def license_revoke(
    lid: str, request: Request, bg: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Response:
    _require_login(request)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    _set_license_status(db, lic, "revoked", "ui/revoke", bg)
    return RedirectResponse(f"/admin/products/{lic.product.slug}", status_code=303)


@router.post("/admin/licenses/{lid}/disable")
def license_disable(
    lid: str, request: Request, bg: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Response:
    """Soft-toggle off. Distinct from revoke — can be flipped back via /enable.
    Same effect on /v1/check while disabled (401 reason=disabled)."""
    _require_login(request)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    _set_license_status(db, lic, "disabled", "ui/disable", bg)
    return RedirectResponse(f"/admin/products/{lic.product.slug}", status_code=303)


@router.post("/admin/licenses/{lid}/enable")
def license_enable(
    lid: str, request: Request, bg: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Response:
    """Flip a disabled or revoked license back to active. ASM clients drop
    upstream_rejected on the next /v1/check (every 24h via Celery beat, or
    immediately on backend restart)."""
    _require_login(request)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    _set_license_status(db, lic, "active", "ui/enable", bg)
    return RedirectResponse(f"/admin/products/{lic.product.slug}", status_code=303)


def _delete_license(db: Session, lic: License, bg: BackgroundTasks | None) -> None:
    # Snapshot fields BEFORE delete so we can fire the webhook with them
    # afterwards (the License row is gone and lic.product / lic.customer
    # become unreachable post-commit).
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
    # COMMIT before firing the webhook -- same race as _set_license_status:
    # the receiver POSTs back into /v1/check synchronously and must see the
    # license is gone (-> 401 invalid_key), not still present in another
    # session's snapshot.
    db.commit()
    if webhook_url and webhook_secret:
        def _deliver() -> None:
            wh.deliver_deleted(
                webhook_url=webhook_url, webhook_secret=webhook_secret, **snapshot
            )
        if bg is not None:
            bg.add_task(_deliver)
        else:
            _deliver()


@router.post("/admin/licenses/{lid}/delete")
def license_delete_one(
    lid: str, request: Request, bg: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Response:
    """Single-row delete (trash-icon path). Bulk delete on the form-level
    submit button still works for multi-select."""
    _require_login(request)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    slug = lic.product.slug
    _delete_license(db, lic, bg)
    return RedirectResponse(f"/admin/products/{slug}?deleted=1", status_code=303)


@router.post("/admin/products/{slug}/licenses/delete")
def licenses_bulk_delete(
    slug: str,
    request: Request,
    bg: BackgroundTasks,
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
        # _delete_license commits per-license + schedules its webhook on
        # bg. Bulk semantics: best-effort, each is independent. The webhook
        # fan-out no longer pins the request thread (M3 fix) -- 20 deletes
        # return as fast as a single delete.
        _delete_license(db, lic, bg)
        deleted += 1
    return RedirectResponse(
        f"/admin/products/{slug}?deleted={deleted}", status_code=303
    )


# ----- customers / events --------------------------------------------------

@router.get("/admin/customers", response_class=HTMLResponse)
def customers_list(request: Request, db: Session = Depends(get_db)) -> Response:
    _require_login(request)
    rows = db.query(Customer).order_by(Customer.created_at.desc()).all()
    # Per-customer product slugs derived from their licenses. Distinct + sorted
    # so the column reads deterministically and sortable-header text sort
    # works as expected. Empty when a customer has no licenses.
    products_by_customer: dict[str, list[str]] = {
        c.id: sorted({lic.product.slug for lic in c.licenses if lic.product})
        for c in rows
    }
    return templates.TemplateResponse(
        request, "customers.html",
        {"customers": rows, "products_by_customer": products_by_customer},
    )


@router.post("/admin/customers/{cid}/edit")
def customer_edit(
    cid: str,
    request: Request,
    name: str = Form(""),
    email: str = Form(...),
    stripe_customer_id: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Edit a customer's name / email / stripe_customer_id. Email is the
    natural-key used by license issuance dedupe, so changing it to an email
    already owned by another customer is rejected (400 via ?error=)."""
    _require_login(request)
    cust = db.query(Customer).filter_by(id=cid).one_or_none()
    if cust is None:
        raise HTTPException(status_code=404)
    new_email = email.strip()
    if not new_email:
        return RedirectResponse("/admin/customers?error=email+required", status_code=303)
    if new_email != cust.email:
        clash = (
            db.query(Customer)
            .filter(Customer.email == new_email, Customer.id != cid)
            .one_or_none()
        )
        if clash is not None:
            return RedirectResponse(
                "/admin/customers?error=email+already+used+by+another+customer",
                status_code=303,
            )
    cust.email = new_email
    cust.name = name.strip() or None
    cust.stripe_customer_id = stripe_customer_id.strip() or None
    db.add(Event(
        type="customer:edited",
        payload={"customer_id": cust.id, "email": cust.email},
        note="ui/customer-edit",
    ))
    db.commit()
    return RedirectResponse(f"/admin/customers?edited={cust.id}", status_code=303)


@router.get("/admin/events", response_class=HTMLResponse)
def events_list(request: Request, db: Session = Depends(get_db)) -> Response:
    _require_login(request)
    rows = db.query(Event).order_by(Event.created_at.desc()).limit(500).all()
    return templates.TemplateResponse(
        request, "events.html", {"events": rows}
    )


@router.get("/admin/events.csv")
def events_csv(request: Request, db: Session = Depends(get_db)) -> Response:
    """Export the events log (most-recent 5000 rows) as CSV. Browser shows
    the OS Save As dialog because of the attachment Content-Disposition."""
    _require_login(request)
    import csv
    import io
    rows = db.query(Event).order_by(Event.created_at.desc()).limit(5000).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["when", "type", "license_id", "product_id", "note", "payload"])
    for e in rows:
        # Payload is a JSON-able dict; serialize for the CSV cell. csv.writer
        # quotes embedded commas/quotes automatically.
        import json
        payload = json.dumps(e.payload or {}, separators=(",", ":"))
        w.writerow([
            e.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            e.type,
            e.license_id or "",
            e.product_id or "",
            e.note or "",
            payload,
        ])
    filename = f"events-{_utcnow().strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(
        buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
