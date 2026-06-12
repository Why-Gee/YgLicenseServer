"""Public + admin JSON API.

Public:
  POST /v1/check                                   — client heartbeat + JWT
  GET  /v1/products/<slug>/pubkey                  — download pub key PEM

Admin (Bearer ADMIN_TOKEN):
  POST /v1/admin/products                          — create product (auto-keypair)
  GET  /v1/admin/products
  GET  /v1/admin/products/<slug>
  POST /v1/admin/products/<slug>/licenses          — issue license
  GET  /v1/admin/products/<slug>/licenses
  POST /v1/admin/licenses/<id>/revoke
  GET  /v1/admin/customers

Heavy lifting lives in `app.services.*`; this module is HTTP plumbing only.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import get_db
from app.models import License
from app.rate_limit import limiter
from app.security import check_admin_bearer
from app.services import customers as customers_svc
from app.services import licenses as licenses_svc
from app.services import products as products_svc
from app.services.check import CheckRejected, check_license
from app.services.errors import Conflict, NotFound, ValidationFailed

log = logging.getLogger("license-server.api")

router = APIRouter()


# ---------- /v1/check ----------------------------------------------------

class CheckIn(BaseModel):
    key: str
    install_id: str
    version: str
    # Optional self-reported webhook URL. Lets a per-tenant client install
    # register its outbound URL during phone-home (no admin UI step).
    # Accepted iff http(s):// and <=500 chars; trailing '/' stripped.
    public_url: str | None = None


class CheckOut(BaseModel):
    jwt: str
    valid_until: datetime
    features: dict
    max_users: int
    license_id: str
    product: str
    # Only present when the URL is self-registered (source='self'); admin-set
    # URLs do not expose the secret over /v1/check.
    webhook_secret: str | None = None


def _client_ip_hash(request: Request) -> str | None:
    """SHA-256 of the immediate-peer IP. We never trust client-supplied
    X-Forwarded-For: Caddy *appends* XFF, so its leftmost entry is whatever
    the client sent — strictly worse than the socket peer. In our deploy
    Caddy is on 127.0.0.1, so request.client.host is the last-hop value
    set by the proxy; trust that and only that. Behind a multi-hop CDN a
    future reader will need to be added that explicitly trusts only the
    rightmost N entries from a configured proxy chain."""
    if request.client is None:
        return None
    return hashlib.sha256(request.client.host.encode()).hexdigest()


@router.post("/v1/check", response_model=CheckOut)
@limiter.limit("60/minute")
def check(body: CheckIn, request: Request, db: Session = Depends(get_db)) -> CheckOut:
    try:
        result = check_license(
            db,
            key=body.key,
            install_id=body.install_id,
            version=body.version,
            public_url=body.public_url,
            client_ip_hash=_client_ip_hash(request),
        )
    except CheckRejected as e:
        raise HTTPException(status_code=e.http_status, detail={"reason": e.reason}) from e
    lic = result.license
    return CheckOut(
        jwt=result.jwt,
        valid_until=lic.valid_until,
        features=lic.features or {},
        max_users=lic.max_users,
        license_id=lic.id,
        product=lic.product.slug,
        webhook_secret=(
            lic.webhook_secret if lic.webhook_url_source == "self" else None
        ),
    )


# ---------- /v1/products/<slug>/pubkey -----------------------------------

@router.get("/v1/products/{slug}/pubkey", response_class=PlainTextResponse)
def get_pubkey(slug: str, db: Session = Depends(get_db)) -> str:
    try:
        p = products_svc.get_product(db, slug)
    except NotFound as e:
        raise HTTPException(status_code=404, detail="product not found") from e
    return p.public_key_pem


# ---------- /v1/admin/* --------------------------------------------------

def _require_admin(
    authorization: str | None = Header(default=None),
    s: Settings = Depends(get_settings),
) -> None:
    if not s.admin_token:
        raise HTTPException(status_code=503, detail="admin disabled (ADMIN_TOKEN unset)")
    if not check_admin_bearer(authorization, s.admin_token):
        raise HTTPException(status_code=401, detail="invalid admin token")


class CreateProductIn(BaseModel):
    slug: str
    name: str
    description: str | None = None
    key_prefix: str
    jwt_issuer: str | None = None
    stripe_webhook_secret: str | None = None
    stripe_api_key: str | None = None


class CreateProductOut(BaseModel):
    id: str
    slug: str
    name: str
    public_key_pem: str
    private_key_warning: str = (
        "Private key stored server-side; back up the database to back it up."
    )


@router.post(
    "/v1/admin/products",
    response_model=CreateProductOut,
    dependencies=[Depends(_require_admin)],
)
def admin_create_product(body: CreateProductIn, db: Session = Depends(get_db)) -> CreateProductOut:
    try:
        p = products_svc.create_product(
            db,
            slug=body.slug, name=body.name, key_prefix=body.key_prefix,
            description=body.description,
            jwt_issuer=body.jwt_issuer,
            stripe_webhook_secret=body.stripe_webhook_secret,
            stripe_api_key=body.stripe_api_key,
            validate_format=True,
        )
    except ValidationFailed as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Conflict as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    return CreateProductOut(id=p.id, slug=p.slug, name=p.name, public_key_pem=p.public_key_pem)


@router.get("/v1/admin/products", dependencies=[Depends(_require_admin)])
def admin_list_products(db: Session = Depends(get_db)) -> list[dict]:
    # Single aggregate query instead of N+1 lazy-loads on `p.licenses`.
    return [
        {
            "id": p.id,
            "slug": p.slug,
            "name": p.name,
            "key_prefix": p.key_prefix,
            "license_count": n,
            "created_at": p.created_at.isoformat(),
        }
        for p, n in products_svc.list_products_with_counts(db)
    ]


@router.get("/v1/admin/products/{slug}", dependencies=[Depends(_require_admin)])
def admin_get_product(slug: str, db: Session = Depends(get_db)) -> dict:
    try:
        p = products_svc.get_product(db, slug)
    except NotFound as e:
        raise HTTPException(status_code=404, detail="product not found") from e
    return {
        "id": p.id,
        "slug": p.slug,
        "name": p.name,
        "description": p.description,
        "key_prefix": p.key_prefix,
        "jwt_issuer": p.jwt_issuer,
        "public_key_pem": p.public_key_pem,
        "stripe_webhook_configured": bool(p.stripe_webhook_secret),
        "license_count": products_svc.license_count(db, p.id),
        "created_at": p.created_at.isoformat(),
    }


class IssueIn(BaseModel):
    email: str
    name: str | None = None
    plan: str = "standard"
    max_users: int = 10
    features: dict = {}
    # First-class AI keys (consumed by ASM license-bundled AI provisioning).
    # None = `features` is authoritative (back-compat). A bool — including
    # False — overrides features["ai_api_included"] explicitly; the cap is
    # only accepted alongside ai_api_included=True and must be > 0.
    ai_api_included: bool | None = None
    ai_included_usd_cap: float | None = None
    valid_days: int = 365
    webhook_url: str | None = None
    allow_http_webhook: bool = False
    stripe_customer_id: str | None = None


class IssueOut(BaseModel):
    license_id: str
    key: str
    valid_until: datetime
    product: str


@router.post(
    "/v1/admin/products/{slug}/licenses",
    response_model=IssueOut,
    dependencies=[Depends(_require_admin)],
)
def admin_issue(slug: str, body: IssueIn, db: Session = Depends(get_db)) -> IssueOut:
    try:
        p = products_svc.get_product(db, slug)
    except NotFound as e:
        raise HTTPException(status_code=404, detail="product not found") from e
    try:
        result = licenses_svc.issue_license(
            db, product=p,
            email=body.email, name=body.name,
            plan=body.plan, max_users=body.max_users,
            valid_days=body.valid_days, features=body.features,
            ai_api_included=body.ai_api_included,
            ai_included_usd_cap=body.ai_included_usd_cap,
            webhook_url=body.webhook_url,
            allow_http_webhook=body.allow_http_webhook,
            stripe_customer_id=body.stripe_customer_id,
            note="admin/issue",
            send_email=True,
        )
    except ValidationFailed as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return IssueOut(
        license_id=result.license.id, key=result.license.key,
        valid_until=result.license.valid_until, product=p.slug,
    )


@router.get("/v1/admin/products/{slug}/licenses", dependencies=[Depends(_require_admin)])
def admin_list_licenses(
    slug: str,
    cursor: str | None = None,
    limit: int | None = None,
    db: Session = Depends(get_db),
) -> dict:
    """Cursor-paginated. Pass the previous response's `next_cursor` back as
    `?cursor=` to fetch the next page; `next_cursor` is null at end-of-set.
    `?limit=` clamps to [1, 500]; defaults to 100. Records ship in created_at
    desc order (newest first)."""
    from app.pagination import clamp_limit, paginate
    try:
        p = products_svc.get_product(db, slug)
    except NotFound as e:
        raise HTTPException(status_code=404, detail="product not found") from e
    base = (
        db.query(License)
        .filter_by(product_id=p.id)
        .order_by(License.created_at.desc(), License.id.desc())
    )
    page = paginate(
        base, cursor_col=(License.created_at, License.id),
        cursor=cursor, limit=clamp_limit(limit),
    )
    return {
        "items": [
            {
                "id": r.id, "key": r.key_display, "plan": r.plan, "status": r.status,
                "max_users": r.max_users, "features": r.features,
                "valid_until": r.valid_until.isoformat(),
                "customer": r.customer.email, "customer_name": r.customer.name,
                "created_at": r.created_at.isoformat(),
                "webhook_url": r.webhook_url,
                "webhook_url_source": r.webhook_url_source,
                "allow_http_webhook": bool(r.allow_http_webhook),
            }
            for r in page.items
        ],
        "next_cursor": page.next_cursor,
    }


@router.post("/v1/admin/licenses/{lid}/revoke", dependencies=[Depends(_require_admin)])
def admin_revoke(lid: str, db: Session = Depends(get_db)) -> dict:
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404, detail="license not found")
    # No schedule= — JSON callers don't have BackgroundTasks. Webhook (if any)
    # fires synchronously after commit. Historically the JSON path didn't
    # fire any webhook at all; now it matches the UI path's behavior.
    licenses_svc.revoke_license(db, lic, note="admin/revoke")
    return {"id": lic.id, "status": lic.status}


@router.get("/v1/admin/customers", dependencies=[Depends(_require_admin)])
def admin_customers(
    cursor: str | None = None,
    limit: int | None = None,
    db: Session = Depends(get_db),
) -> dict:
    """Cursor-paginated. Pass the previous response's `next_cursor` back as
    `?cursor=` to fetch the next page; `next_cursor` is null at end-of-set.
    `?limit=` clamps to [1, 500]; defaults to 100."""
    from app.pagination import clamp_limit
    eff_limit = clamp_limit(limit)
    items, next_cursor = customers_svc.page_customers_with_counts(
        db, cursor=cursor, limit=eff_limit,
    )
    return {
        "items": [
            {
                "id": c.id, "email": c.email, "name": c.name,
                "stripe_customer_id": c.stripe_customer_id,
                "license_count": n,
                "created_at": c.created_at.isoformat(),
            }
            for c, n in items
        ],
        "next_cursor": next_cursor,
    }
