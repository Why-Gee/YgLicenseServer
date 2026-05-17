"""Server-rendered admin UI.

Login uses the admin token as a password (single-user). Session cookie is
HMAC-signed (itsdangerous). Pages render via Jinja2 templates. Form
submissions go to /admin/* routes here; the heavy lifting lives in
`app.services.*`. This module only does request -> service translation and
template rendering.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeSerializer
from markupsafe import Markup
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import __version__
from app.config import get_settings
from app.db import get_db
from app.models import Customer, Event, License, Product
from app.security import check_admin_bearer, check_csrf, csrf_token
from app.services import customers as customers_svc
from app.services import licenses as licenses_svc
from app.services import products as products_svc
from app.services.errors import Conflict, NotFound, Unsafe, ValidationFailed

log = logging.getLogger("license-server.admin")

router = APIRouter()
TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals["app_version"] = __version__
templates.env.globals["csrf_input"] = lambda request: Markup(
    f'<input type="hidden" name="csrf_token" value="{_current_csrf_token(request) or ""}">'
)

# Whitelist of admin-UI error codes -> human-readable messages. Templates
# render `{{ error_message(request.query_params.get('error')) }}` so a
# crafted ?error=<script> can't even show as raw text (autoescape protects
# from XSS, but the visual is still better when constrained to known msgs).
_ERROR_MESSAGES = {
    "slug exists": "A product with that slug already exists.",
    "invalid features json": "Features JSON was not a valid object.",
    "invalid valid_until": "Could not parse Valid Until date.",
    "no products selected": "No products were selected.",
    "no licenses selected": "No licenses were selected.",
    "no webhook configured": "This license has no webhook URL configured.",
    "unsafe webhook url": (
        "Webhook URL refused by SSRF guard "
        "(private/loopback/internal host or non-http(s) scheme)."
    ),
    "email required": "Email is required.",
    "email already used by another customer": "That email is already used by another customer.",
}

# Service-exception messages -> stable UI error codes (used in ?error=<code>).
# Routers translate at the boundary so services stay framework-free.
_SERVICE_ERR_TO_CODE: dict[str, str] = {
    "slug already exists": "slug+exists",
    "invalid features json": "invalid+features+json",
    "invalid valid_until": "invalid+valid_until",
    "unsafe webhook url": "unsafe+webhook+url",
    "no webhook configured": "no+webhook+configured",
    "email required": "email+required",
    "email already used by another customer": "email+already+used+by+another+customer",
}


def _err_code(exc: Exception) -> str:
    """Map a service exception's message to the UI's whitelisted error code.
    Falls back to a generic 'error' so the redirect never explodes."""
    return _SERVICE_ERR_TO_CODE.get(str(exc), "error")


def _error_message(code: str | None) -> str | None:
    """Look up an error code (passed via ?error=) in the whitelist. Unknown
    or missing codes return None, so the template hides the banner instead
    of echoing the raw URL parameter."""
    if not code:
        return None
    return _ERROR_MESSAGES.get(code) or _ERROR_MESSAGES.get(code.replace("+", " "))


templates.env.globals["error_message"] = _error_message

SESSION_COOKIE = "asm_ls_session"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 7  # 7 days


class _LoginRequired(Exception):
    """Raised by handlers when an unauthenticated visitor hits an admin page.
    Caught by an exception handler registered in app.main that returns a
    303 RedirectResponse — keeps each handler free of the redirect plumbing
    while emitting a real redirect (not a JSON HTTPException body).
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
    # Reject ancient cookies even if the signature still verifies. Stolen
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


def _current_csrf_token(request: Request) -> str | None:
    """Derive the expected CSRF token for the request's session cookie. Used
    by templates (via Jinja global `csrf_input`) to render the hidden input.
    Returns None when there's no session cookie -- the login page renders
    without a CSRF guard (POST to /admin/login is exempt; it's the bootstrap)."""
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    s = get_settings()
    if not s.session_secret:
        return None
    return csrf_token(s.session_secret, raw)


def _require_csrf(request: Request, supplied: str | None) -> None:
    """Verify the CSRF token on a state-changing form POST. Raises 403 on
    mismatch. Pulled out so every destructive handler can call it with one
    line; FastAPI Form() captures the value off the form body."""
    raw = request.cookies.get(SESSION_COOKIE)
    s = get_settings()
    if not raw or not s.session_secret or not check_csrf(s.session_secret, raw, supplied):
        client = request.client.host if request.client else "?"
        log.warning("CSRF mismatch on %s from %s", request.url.path, client)
        raise HTTPException(status_code=403, detail="invalid CSRF token")


# ----- login flow --------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
def root(request: Request) -> Response:
    return RedirectResponse("/admin", status_code=303)


@router.get("/admin/login", response_class=HTMLResponse)
def login_form(request: Request, error: str | None = None) -> Response:
    return templates.TemplateResponse(request, "login.html", {"error": error})


@router.post("/admin/login")
def login(request: Request, token: str = Form(...)) -> Response:
    import secrets as _secrets
    s = get_settings()
    if not s.admin_token:
        raise HTTPException(status_code=503, detail="ADMIN_TOKEN not set")
    if not _secrets.compare_digest(token, s.admin_token):
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
def logout(request: Request, csrf_token: str = Form("")) -> Response:
    _require_csrf(request, csrf_token)
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
    recent_events = db.query(Event).order_by(Event.created_at.desc()).limit(20).all()
    return templates.TemplateResponse(
        request, "dashboard.html",
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
    products = products_svc.list_products(db)
    return templates.TemplateResponse(request, "products.html", {"products": products})


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
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    _require_login(request)
    _require_csrf(request, csrf_token)
    try:
        products_svc.create_product(
            db, slug=slug, name=name, key_prefix=key_prefix,
            description=description or None,
            jwt_issuer=jwt_issuer or None,
        )
    except Conflict as e:
        return RedirectResponse(
            f"/admin/products/new?error={_err_code(e)}", status_code=303
        )
    return RedirectResponse(f"/admin/products/{slug}", status_code=303)


@router.post("/admin/products/{slug}/delete")
def product_delete_one(
    slug: str, request: Request, bg: BackgroundTasks,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Single-row delete (trash-icon path)."""
    _require_login(request)
    _require_csrf(request, csrf_token)
    try:
        result = products_svc.delete_product(db, slug)
    except NotFound as e:
        raise HTTPException(status_code=404) from e
    return RedirectResponse(
        f"/admin?deleted_products=1&deleted_licenses={result.license_count}",
        status_code=303,
    )


@router.post("/admin/products/delete")
def products_bulk_delete(
    request: Request,
    bg: BackgroundTasks,
    product_slugs: list[str] = Form(default=[]),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    _require_login(request)
    _require_csrf(request, csrf_token)
    if not product_slugs:
        return RedirectResponse("/admin?error=no+products+selected", status_code=303)
    deleted_products = 0
    deleted_licenses = 0
    for slug in product_slugs:
        try:
            result = products_svc.delete_product(db, slug)
        except NotFound:
            continue
        deleted_licenses += result.license_count
        deleted_products += 1
    return RedirectResponse(
        f"/admin?deleted_products={deleted_products}&deleted_licenses={deleted_licenses}",
        status_code=303,
    )


@router.get("/admin/products/{slug}", response_class=HTMLResponse)
def product_detail(slug: str, request: Request, db: Session = Depends(get_db)) -> Response:
    _require_login(request)
    try:
        p = products_svc.get_product(db, slug)
    except NotFound as e:
        raise HTTPException(status_code=404) from e
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
    try:
        p = products_svc.get_product(db, slug)
    except NotFound as e:
        raise HTTPException(status_code=404) from e
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
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    _require_login(request)
    _require_csrf(request, csrf_token)
    try:
        p = products_svc.get_product(db, slug)
    except NotFound as e:
        raise HTTPException(status_code=404) from e
    try:
        features = json.loads(features_json) if features_json.strip() else {}
        if not isinstance(features, dict):
            raise ValueError
    except (ValueError, json.JSONDecodeError):
        return RedirectResponse(
            f"/admin/products/{slug}?error=invalid+features+json", status_code=303
        )
    try:
        result = licenses_svc.issue_license(
            db, product=p, email=email, name=customer_name,
            plan=plan, max_users=max_users, valid_days=valid_days,
            features=features,
            webhook_url=webhook_url or None,
            note="ui/issue",
        )
    except Unsafe as e:
        return RedirectResponse(
            f"/admin/products/{slug}?error={_err_code(e)}", status_code=303
        )
    return RedirectResponse(
        f"/admin/products/{slug}?issued={result.license.id}", status_code=303
    )


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
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Edit plan / max_users / valid_until / features / webhook config.
    Email + key are not editable. Same redirect contract as /webhook update
    so the secret is shown once when set or rotated."""
    _require_login(request)
    _require_csrf(request, csrf_token)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    try:
        result = licenses_svc.edit_license(
            db, lic,
            plan=plan, max_users=max_users, valid_until_raw=valid_until,
            customer_name=customer_name,
            features_json=features_json,
            webhook_url=webhook_url,
            rotate_secret=rotate_secret == "1",
            note="ui/edit",
            schedule=bg.add_task,
        )
    except (ValidationFailed, Unsafe) as e:
        return RedirectResponse(
            f"/admin/products/{lic.product.slug}?error={_err_code(e)}",
            status_code=303,
        )
    # webhook_lid query param triggers the modal to auto-open with the secret
    # pre-revealed when one was set/rotated; otherwise just `edited` so the
    # banner shows but the modal stays closed.
    new_url = webhook_url.strip() or None
    qp = "webhook_lid" if result.secret_changed and new_url else "edited"
    return RedirectResponse(
        f"/admin/products/{lic.product.slug}?{qp}={lic.id}", status_code=303
    )


@router.post("/admin/licenses/{lid}/webhook")
def license_webhook_update(
    lid: str,
    request: Request,
    webhook_url: str = Form(""),
    rotate_secret: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Set / change / clear the webhook URL on an existing license.
    `rotate_secret=1` regenerates the signing secret (use after the customer
    rotates their receiver key)."""
    _require_login(request)
    _require_csrf(request, csrf_token)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    new_url = webhook_url.strip() or None
    try:
        licenses_svc.configure_webhook(
            db, lic, url=new_url, rotate=rotate_secret == "1",
            mint_on_url_change=True, note="ui/webhook",
        )
    except Unsafe as e:
        return RedirectResponse(
            f"/admin/products/{lic.product.slug}?error={_err_code(e)}",
            status_code=303,
        )
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
    """Programmatic admin endpoint — mirrors the UI form handler with bearer
    auth, JSON I/O, and explicit rotate semantics. The current secret is
    always returned (even when not minted this call) so the caller can
    populate a fresh receiver env file on every boot."""
    _require_admin_bearer(authorization)
    lic = db.query(License).filter_by(id=license_id).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404, detail="license not found")
    new_url = body.url.strip() or None
    try:
        licenses_svc.configure_webhook(
            db, lic, url=new_url, rotate=body.rotate,
            mint_on_url_change=False, note="api/webhook",
            payload_extra={"rotated": body.rotate},
        )
    except Unsafe as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return _WebhookConfigOut(
        webhook_url=lic.webhook_url, webhook_secret=lic.webhook_secret
    )


@router.post("/admin/licenses/{lid}/webhook/test")
def license_webhook_test(
    lid: str, request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Send a synthetic license.status.changed event to the configured URL.
    Useful right after issuance to confirm the customer's receiver works."""
    _require_login(request)
    _require_csrf(request, csrf_token)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    try:
        result = licenses_svc.test_webhook(lic)
    except ValidationFailed as e:
        return RedirectResponse(
            f"/admin/products/{lic.product.slug}?error={_err_code(e)}",
            status_code=303,
        )
    qs = (
        f"webhook_test_lid={lic.id}&webhook_test_ok={int(result.ok)}"
        f"&webhook_test_status={result.status or ''}"
    )
    return RedirectResponse(f"/admin/products/{lic.product.slug}?{qs}", status_code=303)


@router.post("/admin/licenses/{lid}/revoke")
def license_revoke(
    lid: str, request: Request, bg: BackgroundTasks,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    _require_login(request)
    _require_csrf(request, csrf_token)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    licenses_svc.revoke_license(db, lic, note="ui/revoke", schedule=bg.add_task)
    return RedirectResponse(f"/admin/products/{lic.product.slug}", status_code=303)


@router.post("/admin/licenses/{lid}/disable")
def license_disable(
    lid: str, request: Request, bg: BackgroundTasks,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Soft-toggle off. Distinct from revoke — can be flipped back via /enable.
    Same effect on /v1/check while disabled (401 reason=disabled)."""
    _require_login(request)
    _require_csrf(request, csrf_token)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    licenses_svc.disable_license(db, lic, note="ui/disable", schedule=bg.add_task)
    return RedirectResponse(f"/admin/products/{lic.product.slug}", status_code=303)


@router.post("/admin/licenses/{lid}/enable")
def license_enable(
    lid: str, request: Request, bg: BackgroundTasks,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Flip a disabled or revoked license back to active. ASM clients drop
    upstream_rejected on the next /v1/check (every 24h via Celery beat, or
    immediately on backend restart)."""
    _require_login(request)
    _require_csrf(request, csrf_token)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    licenses_svc.enable_license(db, lic, note="ui/enable", schedule=bg.add_task)
    return RedirectResponse(f"/admin/products/{lic.product.slug}", status_code=303)


@router.post("/admin/licenses/{lid}/delete")
def license_delete_one(
    lid: str, request: Request, bg: BackgroundTasks,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Single-row delete (trash-icon path). Bulk delete on the form-level
    submit button still works for multi-select."""
    _require_login(request)
    _require_csrf(request, csrf_token)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    slug = lic.product.slug
    licenses_svc.delete_license(db, lic, schedule=bg.add_task, note="ui/delete")
    return RedirectResponse(f"/admin/products/{slug}?deleted=1", status_code=303)


@router.post("/admin/products/{slug}/licenses/delete")
def licenses_bulk_delete(
    slug: str,
    request: Request,
    bg: BackgroundTasks,
    license_ids: list[str] = Form(default=[]),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    _require_login(request)
    _require_csrf(request, csrf_token)
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
        licenses_svc.delete_license(db, lic, schedule=bg.add_task, note="ui/delete")
        deleted += 1
    return RedirectResponse(
        f"/admin/products/{slug}?deleted={deleted}", status_code=303
    )


# ----- customers / events -------------------------------------------------

@router.get("/admin/customers", response_class=HTMLResponse)
def customers_list(request: Request, db: Session = Depends(get_db)) -> Response:
    _require_login(request)
    rows = db.query(Customer).order_by(Customer.created_at.desc()).all()
    # Per-customer product slugs derived from their licenses. Distinct + sorted
    # so the column reads deterministically and sortable-header text sort
    # works as expected.
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
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Edit a customer's name / email / stripe_customer_id. Email is the
    natural-key used by license issuance dedupe, so changing it to an email
    already owned by another customer is rejected (400 via ?error=)."""
    _require_login(request)
    _require_csrf(request, csrf_token)
    try:
        cust = customers_svc.edit_customer(
            db, cid, email=email, name=name,
            stripe_customer_id=stripe_customer_id,
            note="ui/customer-edit",
        )
    except NotFound as e:
        raise HTTPException(status_code=404) from e
    except (Conflict, ValidationFailed) as e:
        return RedirectResponse(
            f"/admin/customers?error={_err_code(e)}", status_code=303
        )
    return RedirectResponse(f"/admin/customers?edited={cust.id}", status_code=303)


@router.get("/admin/events", response_class=HTMLResponse)
def events_list(request: Request, db: Session = Depends(get_db)) -> Response:
    _require_login(request)
    rows = db.query(Event).order_by(Event.created_at.desc()).limit(500).all()
    return templates.TemplateResponse(request, "events.html", {"events": rows})


@router.get("/admin/events.csv")
def events_csv(request: Request, db: Session = Depends(get_db)) -> Response:
    """Export the events log (most-recent 5000 rows) as CSV. Browser shows
    the OS Save As dialog because of the attachment Content-Disposition."""
    _require_login(request)
    rows = db.query(Event).order_by(Event.created_at.desc()).limit(5000).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["when", "type", "license_id", "product_id", "note", "payload"])
    for e in rows:
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
