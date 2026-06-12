"""License operations: issue, edit, status transitions, webhook config,
webhook test, delete, bulk-delete. Plus the bearer-auth /admin/api/licenses
JSON sister endpoint."""
from __future__ import annotations

import json

from fastapi import APIRouter, BackgroundTasks, Depends, Form, Header, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import get_db
from app.models import License, Product
from app.routers.admin_ui._deps import err_code, require_csrf, require_login
from app.security import check_admin_bearer
from app.services import licenses as licenses_svc
from app.services import products as products_svc
from app.services.errors import NotFound, Unsafe, ValidationFailed

router = APIRouter()


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
    ai_api_included: str = Form(""),
    ai_included_usd_cap: str = Form(""),
    webhook_url: str = Form(""),
    allow_http_webhook: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
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
            # Checkbox semantics: absent/empty = explicit False (never None) —
            # the form always authors the toggle, so toggle-off writes
            # ai_api_included: false into features rather than omitting it.
            ai_api_included=(ai_api_included == "1"),
            ai_included_usd_cap=licenses_svc.parse_usd_cap(ai_included_usd_cap),
            webhook_url=webhook_url or None,
            allow_http_webhook=(allow_http_webhook == "1"),
            note="ui/issue",
            # UI used to skip this and admins were copy-pasting keys by
            # hand. Match the JSON API which has always sent on issue.
            send_email=True,
        )
    except (ValidationFailed, Unsafe) as e:
        return RedirectResponse(
            f"/admin/products/{slug}?error={err_code(e)}", status_code=303
        )
    # Plaintext appears in this query string for ~1 request; acceptable
    # trade-off for the single-op deployment shape — admin owns their access logs.
    from urllib.parse import quote
    return RedirectResponse(
        f"/admin/products/{slug}?issued={result.license.id}&key={quote(result.license.key)}",
        status_code=303,
    )


@router.post("/admin/licenses/{lid}/edit")
def license_edit(
    lid: str,
    request: Request,
    bg: BackgroundTasks,
    plan: str = Form(...),
    max_users: int = Form(...),
    valid_until: str = Form(...),
    features_json: str = Form("{}"),
    ai_api_included: str = Form(""),
    ai_included_usd_cap: str = Form(""),
    webhook_url: str = Form(""),
    allow_http_webhook: str = Form(""),
    rotate_secret: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Edit plan / max_users / valid_until / features / webhook config.
    Email + key are not editable. Customer-side fields (name, stripe id) are
    edited via /admin/customers/{id}/edit -- a Customer is tenant-wide, so
    renaming via a license form would silently affect their other products.
    Same redirect contract as /webhook update so the secret is shown once
    when set or rotated."""
    require_login(request)
    require_csrf(request, csrf_token)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    try:
        result = licenses_svc.edit_license(
            db, lic,
            plan=plan, max_users=max_users, valid_until_raw=valid_until,
            features_json=features_json,
            # Same checkbox semantics as issue: absent = explicit False, so
            # un-ticking the toggle persists ai_api_included: false.
            ai_api_included=(ai_api_included == "1"),
            ai_included_usd_cap=licenses_svc.parse_usd_cap(ai_included_usd_cap),
            webhook_url=webhook_url,
            allow_http_webhook=(allow_http_webhook == "1") if allow_http_webhook else None,
            rotate_secret=rotate_secret == "1",
            note="ui/edit",
            schedule=bg.add_task,
        )
    except (ValidationFailed, Unsafe) as e:
        return RedirectResponse(
            f"/admin/products/{lic.product.slug}?error={err_code(e)}",
            status_code=303,
        )
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
    allow_http_webhook: str = Form(""),
    rotate_secret: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Set / change / clear the webhook URL on an existing license.
    `rotate_secret=1` regenerates the signing secret."""
    require_login(request)
    require_csrf(request, csrf_token)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    new_url = webhook_url.strip() or None
    try:
        licenses_svc.configure_webhook(
            db, lic, url=new_url, rotate=rotate_secret == "1",
            mint_on_url_change=True,
            allow_http=(allow_http_webhook == "1"),
            note="ui/webhook",
        )
    except Unsafe as e:
        return RedirectResponse(
            f"/admin/products/{lic.product.slug}?error={err_code(e)}",
            status_code=303,
        )
    return RedirectResponse(
        f"/admin/products/{lic.product.slug}?webhook_lid={lic.id}", status_code=303
    )


# ----- programmatic admin API (Bearer ADMIN_TOKEN) -----------------------
# Bearer-token sister of the form-driven /admin/licenses/{lid}/webhook
# above. Lets external scripts (e.g. a client-side startup script spinning
# up a fresh tunnel on each boot) wire the receiver URL + read back the
# signing secret without driving the admin UI.

class _WebhookConfigIn(BaseModel):
    url: str  # required; empty string clears (delete url + secret)
    rotate: bool = False
    # Optional per-license http:// opt-in. None = preserve existing flag;
    # True = allow http:// on this license; False = revoke. Matches the
    # admin-UI checkbox semantics on the form-driven webhook endpoint.
    allow_http: bool | None = None


class _WebhookConfigOut(BaseModel):
    webhook_url: str | None
    webhook_secret: str | None


def _require_admin_bearer(
    authorization: str | None = Header(default=None),
    s: Settings = Depends(get_settings),
) -> None:
    if not s.admin_token:
        raise HTTPException(status_code=503, detail="admin disabled (ADMIN_TOKEN unset)")
    if not check_admin_bearer(authorization, s.admin_token):
        raise HTTPException(status_code=401, detail="invalid admin token")


@router.post(
    "/admin/api/licenses/{license_id}/webhook",
    response_model=_WebhookConfigOut,
    dependencies=[Depends(_require_admin_bearer)],
)
def admin_api_webhook_set(
    license_id: str,
    body: _WebhookConfigIn,
    db: Session = Depends(get_db),
) -> _WebhookConfigOut:
    lic = db.query(License).filter_by(id=license_id).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404, detail="license not found")
    new_url = body.url.strip() or None
    try:
        licenses_svc.configure_webhook(
            db, lic, url=new_url, rotate=body.rotate,
            mint_on_url_change=False,
            allow_http=body.allow_http,
            note="api/webhook",
            payload_extra={"rotated": body.rotate},
        )
    except Unsafe as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return _WebhookConfigOut(
        webhook_url=lic.webhook_url, webhook_secret=lic.webhook_secret
    )


@router.post("/admin/licenses/{lid}/webhook/convert-to-self")
def license_webhook_convert_to_self(
    lid: str, request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Flip an admin-set webhook to source='self' in one click. Keeps URL,
    rotates secret. See docs/v1.0-workouttracker-client-findings.md item 1."""
    require_login(request)
    require_csrf(request, csrf_token)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    try:
        licenses_svc.convert_webhook_to_self(db, lic, note="ui/convert-to-self")
    except ValidationFailed as e:
        return RedirectResponse(
            f"/admin/products/{lic.product.slug}?error={err_code(e)}",
            status_code=303,
        )
    # Same redirect contract as /webhook update -- modal auto-opens with the
    # newly-minted secret revealed once.
    return RedirectResponse(
        f"/admin/products/{lic.product.slug}?webhook_lid={lic.id}", status_code=303
    )


@router.post("/admin/licenses/{lid}/webhook/test")
def license_webhook_test(
    lid: str, request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Send a synthetic license.status.changed event to the configured URL.
    Useful right after issuance to confirm the customer's receiver works."""
    require_login(request)
    require_csrf(request, csrf_token)
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404)
    try:
        result = licenses_svc.test_webhook(lic)
    except ValidationFailed as e:
        return RedirectResponse(
            f"/admin/products/{lic.product.slug}?error={err_code(e)}",
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
    require_login(request)
    require_csrf(request, csrf_token)
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
    """Soft-toggle off. Distinct from revoke — can be flipped back via /enable."""
    require_login(request)
    require_csrf(request, csrf_token)
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
    """Flip a disabled or revoked license back to active."""
    require_login(request)
    require_csrf(request, csrf_token)
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
    require_login(request)
    require_csrf(request, csrf_token)
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
    require_login(request)
    require_csrf(request, csrf_token)
    p = db.query(Product).filter_by(slug=slug).one_or_none()
    if p is None:
        raise HTTPException(status_code=404)
    if not license_ids:
        return RedirectResponse(
            f"/admin/products/{slug}?error=no+licenses+selected", status_code=303
        )
    # Resolve all license rows first, scoped to this product so a hostile
    # form payload can't reach across products. IDs that don't match are
    # silently skipped (same behavior as the single-row path -- the worst a
    # crafted form can do is no-op).
    rows = (
        db.query(License)
        .filter(License.product_id == p.id, License.id.in_(license_ids))
        .all()
    )
    # One transaction for the whole batch -- partial failure rolls back the
    # entire group rather than leaving the table half-deleted.
    snapshots = licenses_svc.delete_licenses_bulk(
        db, rows, schedule=bg.add_task, note="ui/bulk-delete",
    )
    return RedirectResponse(
        f"/admin/products/{slug}?deleted={len(snapshots)}", status_code=303
    )
