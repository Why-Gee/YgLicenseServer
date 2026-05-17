"""Product lifecycle. Pure business logic — no FastAPI, no Request."""
from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.keystore import encrypt_secret
from app.models import Event, License, Product
from app.services.errors import Conflict, NotFound, ValidationFailed
from app.signing import generate_keypair

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_PREFIX_RE = re.compile(r"^[a-z0-9_]{1,15}$")


@dataclass(frozen=True)
class ProductDeletion:
    """Result of a cascading product delete. `license_count` is the number
    of licenses removed; the router uses it for the post-redirect counter."""

    license_count: int


def create_product(
    db: Session,
    *,
    slug: str,
    name: str,
    key_prefix: str,
    description: str | None = None,
    jwt_issuer: str | None = None,
    stripe_webhook_secret: str | None = None,
    stripe_api_key: str | None = None,
    validate_format: bool = False,
) -> Product:
    """Create a product + auto-generated Ed25519 keypair (encrypted at rest).

    `validate_format=True` runs the strict slug/key_prefix regex; the JSON
    API uses it. The form-driven UI path historically didn't, so the default
    is off to preserve behavior — tighten in a follow-up.
    """
    if validate_format:
        if not _SLUG_RE.match(slug):
            raise ValidationFailed("invalid slug (lowercase a-z0-9-, max 63)")
        if not _PREFIX_RE.match(key_prefix):
            raise ValidationFailed("invalid key_prefix (lowercase a-z0-9_, max 15)")
    if db.query(Product).filter_by(slug=slug).one_or_none() is not None:
        raise Conflict("slug already exists")

    priv_pem, pub_pem = generate_keypair()
    p = Product(
        slug=slug,
        name=name,
        description=description or None,
        public_key_pem=pub_pem,
        # All three secret fields wrap under the same KEK envelope. None
        # passes through so a product can be created without Stripe wiring.
        private_key_pem=encrypt_secret(priv_pem),
        key_prefix=key_prefix,
        stripe_webhook_secret=encrypt_secret(stripe_webhook_secret),
        stripe_api_key=encrypt_secret(stripe_api_key),
        jwt_issuer=jwt_issuer or f"{slug}-license-server",
    )
    db.add(p)
    db.add(Event(product_id=p.id, type="product:created", payload={"slug": slug}))
    db.commit()
    db.refresh(p)
    return p


def get_product(db: Session, slug: str) -> Product:
    p = db.query(Product).filter_by(slug=slug).one_or_none()
    if p is None:
        raise NotFound("product not found")
    return p


def delete_product(
    db: Session, slug: str, *,
    schedule=None,  # Scheduler from licenses module; left untyped to avoid the circular import.
) -> ProductDeletion:
    """Delete a product + cascade everything underneath in a single transaction.

    Customers are NOT deleted (they may own licenses for other products on
    this server). Events tied to this product survive with product_id NULL'd
    so the audit trail keeps the history; the polymorphic (subject_kind,
    subject_id) added in v0.8.1 keeps them queryable.

    All license rows owned by this product are staged for deletion inside the
    same transaction as the product row itself; one commit at the end. Either
    everything goes or nothing does. Per-license `license.deleted` webhooks
    fan out after the commit succeeds so a hostile receiver can never see a
    state that the DB then rolled back.
    """
    # Local import keeps the service modules importable from each other
    # without ordering pain.
    from app.services.licenses import _delete_license_in_tx, _fire_deleted_webhook, _run

    p = db.query(Product).filter_by(slug=slug).one_or_none()
    if p is None:
        raise NotFound("product not found")
    licenses = db.query(License).filter_by(product_id=p.id).all()
    snapshots = [_delete_license_in_tx(db, lic, note="service/product-cascade") for lic in licenses]
    license_count = len(licenses)
    db.add(Event(
        type="product:deleted",
        payload={
            "product_id": p.id, "slug": p.slug, "name": p.name,
            "license_count": license_count,
        },
        note="service/delete",
    ))
    db.query(Event).filter_by(product_id=p.id).update({"product_id": None})
    db.delete(p)
    db.commit()
    for snap in snapshots:
        _run(lambda s=snap: _fire_deleted_webhook(s), schedule)
    return ProductDeletion(license_count=license_count)


def list_products(db: Session) -> list[Product]:
    return list(db.query(Product).order_by(Product.created_at.desc()).all())


def list_products_with_counts(db: Session) -> list[tuple[Product, int]]:
    """Same as list_products, but pairs each product with its license count
    via a single aggregate query. Use this whenever the caller is going to
    render `len(p.licenses)` -- the ORM lazy-load would otherwise issue one
    SELECT per product (N+1)."""
    rows = (
        db.query(Product, func.count(License.id))
        .outerjoin(License, License.product_id == Product.id)
        .group_by(Product.id)
        .order_by(Product.created_at.desc())
        .all()
    )
    return [(p, int(n)) for p, n in rows]


def license_count(db: Session, product_id: str) -> int:
    """Single SELECT COUNT for a single product. Used by detail endpoints
    that already hold the product row and just need the count."""
    return int(
        db.query(func.count(License.id))
        .filter(License.product_id == product_id)
        .scalar() or 0
    )
