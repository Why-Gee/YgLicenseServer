"""Per-product Stripe webhook handler.

Endpoint is product-scoped: /v1/products/<slug>/stripe-webhook.
Each product carries its own webhook secret, so multiple Stripe accounts
(or test/live mode pairs) can sign for distinct products without collision.

Handles:
  invoice.paid              -> extend valid_until 30d, status=active
  invoice.payment_failed    -> status=delinquent
  customer.subscription.deleted -> status=revoked
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta

import stripe
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Customer, Event, License, Product

log = logging.getLogger("license-server.stripe")
router = APIRouter()


@router.post("/v1/products/{slug}/stripe-webhook")
async def stripe_webhook(
    slug: str,
    request: Request,
    stripe_signature: str = Header(default=""),
    db: Session = Depends(get_db),
) -> dict:
    p = db.query(Product).filter_by(slug=slug).one_or_none()
    if p is None:
        raise HTTPException(status_code=404, detail="product not found")
    if not p.stripe_webhook_secret:
        raise HTTPException(status_code=503, detail="webhook secret not configured for product")

    payload = await request.body()
    try:
        event = stripe.Webhook.construct_event(payload, stripe_signature, p.stripe_webhook_secret)
    except (ValueError, stripe.error.SignatureVerificationError) as e:
        log.warning("invalid stripe webhook for %s: %s", slug, e)
        raise HTTPException(status_code=400, detail="invalid signature") from e

    event_type = event["type"]
    obj = event["data"]["object"]
    customer_id = obj.get("customer")

    if event_type == "invoice.paid":
        _extend_or_create(db, product=p, customer_id=customer_id, email=obj.get("customer_email"))
    elif event_type == "invoice.payment_failed":
        _mark_status(db, product=p, customer_id=customer_id, status="delinquent", note=event_type)
    elif event_type == "customer.subscription.deleted":
        _mark_status(db, product=p, customer_id=customer_id, status="revoked", note=event_type)
    else:
        log.info("ignored stripe event for %s: %s", slug, event_type)

    db.commit()
    return {"received": True, "type": event_type, "product": slug}


def _extend_or_create(
    db: Session, *, product: Product, customer_id: str | None, email: str | None
) -> None:
    if not customer_id:
        return
    cust = db.query(Customer).filter_by(stripe_customer_id=customer_id).one_or_none()
    if cust is None:
        if not email:
            log.warning("invoice.paid for unknown customer %s without email", customer_id)
            return
        cust = Customer(stripe_customer_id=customer_id, email=email)
        db.add(cust)
        db.flush()
    lic = (
        db.query(License)
        .filter_by(customer_id=cust.id, product_id=product.id)
        .order_by(License.created_at.desc())
        .first()
    )
    if lic is None:
        key = f"{product.key_prefix}_" + secrets.token_urlsafe(32)
        lic = License(
            product_id=product.id,
            customer_id=cust.id,
            key=key,
            plan="standard",
            max_users=10,
            features={},
            valid_until=datetime.utcnow() + timedelta(days=30),
            status="active",
        )
        db.add(lic)
        db.add(Event(
            license_id=lic.id, product_id=product.id,
            type="issued", payload={}, note="stripe invoice.paid",
        ))
    else:
        floor = datetime.utcnow()
        base = max(lic.valid_until, floor)
        lic.valid_until = base + timedelta(days=30)
        lic.status = "active"
        db.add(Event(
            license_id=lic.id, product_id=product.id, type="extended",
            payload={"new_valid_until": lic.valid_until.isoformat()},
        ))


def _mark_status(
    db: Session, *, product: Product, customer_id: str | None, status: str, note: str
) -> None:
    if not customer_id:
        return
    cust = db.query(Customer).filter_by(stripe_customer_id=customer_id).one_or_none()
    if cust is None:
        return
    for lic in cust.licenses:
        if lic.product_id != product.id:
            continue
        lic.status = status
        db.add(Event(
            license_id=lic.id, product_id=product.id,
            type=f"status:{status}", payload={}, note=note,
        ))
