"""Per-product Stripe webhook handler.

Endpoint is product-scoped: /v1/products/<slug>/stripe-webhook.
Each product carries its own webhook secret, so multiple Stripe accounts
(or test/live mode pairs) can sign for distinct products without collision.

Handles:
  invoice.paid              -> extend valid_until 30d, status=active
  invoice.payment_failed    -> status=delinquent
  customer.subscription.deleted -> status=revoked

Idempotency: every successfully signed event is recorded by event.id in the
processed_stripe_events table BEFORE any side effects fire. A redelivered
event (same id) short-circuits without mutating any license. Stripe retries
the same event on receiver 5xx/timeout, so this guard is load-bearing.
"""
from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta

import stripe
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

# `SignatureVerificationError` lived at `stripe.error.SignatureVerificationError`
# in older releases and moved to a top-level alias on stripe>=8. Import the
# top-level name with a fallback so we work on both shapes without pinning.
try:  # pragma: no cover - import-time compat
    from stripe import SignatureVerificationError
except ImportError:  # pragma: no cover
    from stripe.error import SignatureVerificationError  # type: ignore[no-redef]

from app.db import get_db
from app.email import send_license_email
from app.models import Customer, Event, License, ProcessedStripeEvent, Product

log = logging.getLogger("license-server.stripe")
router = APIRouter()


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


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
    except (ValueError, SignatureVerificationError) as e:
        log.warning("invalid stripe webhook for %s: %s", slug, e)
        raise HTTPException(status_code=400, detail="invalid signature") from e

    event_id = event.get("id")
    event_type = event["type"]
    if not event_id:
        # No id = malformed event. Process best-effort but don't index it.
        log.warning("stripe event missing id for %s: %s", slug, event_type)
    else:
        # Idempotency guard: claim the event.id by inserting into the
        # dedup table inside its own savepoint. A duplicate delivery
        # collides on PK -> we 200 immediately without firing side effects.
        already_processed = (
            db.query(ProcessedStripeEvent).filter_by(id=event_id).one_or_none()
        )
        if already_processed is not None:
            log.info("stripe event %s already processed; skipping", event_id)
            return {"received": True, "type": event_type, "product": slug, "duplicate": True}
        db.add(ProcessedStripeEvent(id=event_id, product_id=p.id, type=event_type))
        try:
            db.flush()
        except IntegrityError:
            # Lost a race against a concurrent delivery of the same event.
            db.rollback()
            log.info("stripe event %s claimed by concurrent delivery; skipping", event_id)
            return {"received": True, "type": event_type, "product": slug, "duplicate": True}

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
            valid_until=_utcnow() + timedelta(days=30),
            status="active",
        )
        db.add(lic)
        db.add(Event(
            license_id=lic.id, product_id=product.id,
            type="issued", payload={}, note="stripe invoice.paid",
        ))
        send_license_email(to=cust.email, key=key, product_name=product.name)
    else:
        floor = _utcnow()
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
