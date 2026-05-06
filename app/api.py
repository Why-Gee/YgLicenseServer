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
"""
from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.email import send_license_email
from app.models import Customer, Event, Install, License, Product
from app.signing import generate_keypair, sign_license_jwt

router = APIRouter()

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_PREFIX_RE = re.compile(r"^[a-z0-9_]{1,15}$")


# ---------- /v1/check ----------------------------------------------------

class CheckIn(BaseModel):
    key: str
    install_id: str
    version: str


class CheckOut(BaseModel):
    jwt: str
    valid_until: datetime
    features: dict
    max_users: int
    license_id: str
    product: str


@router.post("/v1/check", response_model=CheckOut)
def check(body: CheckIn, request: Request, db: Session = Depends(get_db)) -> CheckOut:
    lic = db.query(License).filter_by(key=body.key).one_or_none()
    if lic is None:
        raise HTTPException(status_code=401, detail={"reason": "invalid_key"})
    if lic.status == "revoked":
        raise HTTPException(status_code=401, detail={"reason": "revoked"})
    if lic.status == "disabled":
        raise HTTPException(status_code=401, detail={"reason": "disabled"})
    if lic.valid_until < datetime.utcnow():
        raise HTTPException(status_code=401, detail={"reason": "expired"})

    ip_hash = (
        hashlib.sha256((request.client.host if request.client else "").encode()).hexdigest()
        if request.client else None
    )
    install = (
        db.query(Install)
        .filter_by(license_id=lic.id, install_id=body.install_id)
        .one_or_none()
    )
    if install is None:
        install = Install(
            license_id=lic.id,
            install_id=body.install_id,
            version=body.version,
            ip_addr_hash=ip_hash,
        )
        db.add(install)
    else:
        install.version = body.version
        install.last_seen_at = datetime.utcnow()
        install.ip_addr_hash = ip_hash

    token, _exp = sign_license_jwt(
        product=lic.product,
        license_id=lic.id,
        install_id=body.install_id,
        plan=lic.plan,
        max_users=lic.max_users,
        features=lic.features or {},
        valid_until=lic.valid_until,
    )
    db.add(Event(
        license_id=lic.id,
        product_id=lic.product_id,
        type="heartbeat",
        payload={"version": body.version, "install_id": body.install_id},
    ))
    db.commit()
    return CheckOut(
        jwt=token,
        valid_until=lic.valid_until,
        features=lic.features or {},
        max_users=lic.max_users,
        license_id=lic.id,
        product=lic.product.slug,
    )


# ---------- /v1/products/<slug>/pubkey -----------------------------------

@router.get("/v1/products/{slug}/pubkey", response_class=PlainTextResponse)
def get_pubkey(slug: str, db: Session = Depends(get_db)) -> str:
    p = db.query(Product).filter_by(slug=slug).one_or_none()
    if p is None:
        raise HTTPException(status_code=404, detail="product not found")
    return p.public_key_pem


# ---------- /v1/admin/* --------------------------------------------------

def _require_admin(authorization: str | None = Header(default=None)) -> None:
    s = get_settings()
    if not s.admin_token:
        raise HTTPException(status_code=503, detail="admin disabled (ADMIN_TOKEN unset)")
    if authorization != f"Bearer {s.admin_token}":
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
    if not _SLUG_RE.match(body.slug):
        raise HTTPException(status_code=400, detail="invalid slug (lowercase a-z0-9-, max 63)")
    if not _PREFIX_RE.match(body.key_prefix):
        raise HTTPException(status_code=400, detail="invalid key_prefix (lowercase a-z0-9_, max 15)")
    if db.query(Product).filter_by(slug=body.slug).one_or_none():
        raise HTTPException(status_code=409, detail="slug already exists")

    priv_pem, pub_pem = generate_keypair()
    p = Product(
        slug=body.slug,
        name=body.name,
        description=body.description,
        public_key_pem=pub_pem,
        private_key_pem=priv_pem,
        key_prefix=body.key_prefix,
        stripe_webhook_secret=body.stripe_webhook_secret,
        stripe_api_key=body.stripe_api_key,
        jwt_issuer=body.jwt_issuer or f"{body.slug}-license-server",
    )
    db.add(p)
    db.add(Event(product_id=p.id, type="product:created", payload={"slug": body.slug}))
    db.commit()
    db.refresh(p)
    return CreateProductOut(id=p.id, slug=p.slug, name=p.name, public_key_pem=p.public_key_pem)


@router.get("/v1/admin/products", dependencies=[Depends(_require_admin)])
def admin_list_products(db: Session = Depends(get_db)) -> list[dict]:
    return [
        {
            "id": p.id,
            "slug": p.slug,
            "name": p.name,
            "key_prefix": p.key_prefix,
            "license_count": len(p.licenses),
            "created_at": p.created_at.isoformat(),
        }
        for p in db.query(Product).order_by(Product.created_at.desc()).all()
    ]


@router.get("/v1/admin/products/{slug}", dependencies=[Depends(_require_admin)])
def admin_get_product(slug: str, db: Session = Depends(get_db)) -> dict:
    p = db.query(Product).filter_by(slug=slug).one_or_none()
    if p is None:
        raise HTTPException(status_code=404, detail="product not found")
    return {
        "id": p.id,
        "slug": p.slug,
        "name": p.name,
        "description": p.description,
        "key_prefix": p.key_prefix,
        "jwt_issuer": p.jwt_issuer,
        "public_key_pem": p.public_key_pem,
        "stripe_webhook_configured": bool(p.stripe_webhook_secret),
        "license_count": len(p.licenses),
        "created_at": p.created_at.isoformat(),
    }


class IssueIn(BaseModel):
    email: str
    plan: str = "standard"
    max_users: int = 10
    features: dict = {}
    valid_days: int = 365
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
    p = db.query(Product).filter_by(slug=slug).one_or_none()
    if p is None:
        raise HTTPException(status_code=404, detail="product not found")
    cust = (
        db.query(Customer).filter_by(email=body.email).one_or_none()
        if body.stripe_customer_id is None
        else db.query(Customer).filter_by(stripe_customer_id=body.stripe_customer_id).one_or_none()
    )
    if cust is None:
        cust = Customer(email=body.email, stripe_customer_id=body.stripe_customer_id)
        db.add(cust)
        db.flush()
    key = f"{p.key_prefix}_" + secrets.token_urlsafe(32)
    lic = License(
        product_id=p.id,
        customer_id=cust.id,
        key=key,
        plan=body.plan,
        max_users=body.max_users,
        features=body.features,
        valid_until=datetime.utcnow() + timedelta(days=body.valid_days),
        status="active",
    )
    db.add(lic)
    db.add(Event(
        license_id=lic.id, product_id=p.id, type="issued",
        payload={"plan": body.plan}, note="admin/issue",
    ))
    db.commit()
    db.refresh(lic)
    send_license_email(to=cust.email, key=lic.key, product_name=p.name)
    return IssueOut(license_id=lic.id, key=lic.key, valid_until=lic.valid_until, product=p.slug)


@router.get("/v1/admin/products/{slug}/licenses", dependencies=[Depends(_require_admin)])
def admin_list_licenses(slug: str, limit: int = 200, db: Session = Depends(get_db)) -> list[dict]:
    p = db.query(Product).filter_by(slug=slug).one_or_none()
    if p is None:
        raise HTTPException(status_code=404, detail="product not found")
    rows = (
        db.query(License)
        .filter_by(product_id=p.id)
        .order_by(License.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": r.id,
            "key": r.key,
            "plan": r.plan,
            "status": r.status,
            "max_users": r.max_users,
            "features": r.features,
            "valid_until": r.valid_until.isoformat(),
            "customer": r.customer.email,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@router.post("/v1/admin/licenses/{lid}/revoke", dependencies=[Depends(_require_admin)])
def admin_revoke(lid: str, db: Session = Depends(get_db)) -> dict:
    lic = db.query(License).filter_by(id=lid).one_or_none()
    if lic is None:
        raise HTTPException(status_code=404, detail="license not found")
    lic.status = "revoked"
    db.add(Event(
        license_id=lic.id, product_id=lic.product_id, type="status:revoked",
        note="admin/revoke",
    ))
    db.commit()
    return {"id": lic.id, "status": lic.status}


@router.get("/v1/admin/customers", dependencies=[Depends(_require_admin)])
def admin_customers(db: Session = Depends(get_db)) -> list[dict]:
    return [
        {
            "id": c.id,
            "email": c.email,
            "stripe_customer_id": c.stripe_customer_id,
            "license_count": len(c.licenses),
            "created_at": c.created_at.isoformat(),
        }
        for c in db.query(Customer).order_by(Customer.created_at.desc()).all()
    ]
