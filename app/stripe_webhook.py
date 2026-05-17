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
from collections.abc import Callable
from datetime import timedelta

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

from app._time import utcnow as _utcnow
from app.db import get_db
from app.email import send_license_email
from app.keystore import decrypt_secret
from app.models import Customer, Event, License, ProcessedStripeEvent, Product

log = logging.getLogger("license-server.stripe")
router = APIRouter()


# Stripe event-type -> handler. Each handler takes (db, product, event) and
# applies the side effect; missing types are logged and 200'd. Register new
# types with @stripe_handler("event.name") rather than editing a dispatch chain.
Handler = Callable[[Session, "Product", dict], None]
_HANDLERS: dict[str, Handler] = {}


def stripe_handler(event_type: str) -> Callable[[Handler], Handler]:
    def decorate(fn: Handler) -> Handler:
        if event_type in _HANDLERS:
            raise RuntimeError(f"duplicate stripe handler for {event_type}")
        _HANDLERS[event_type] = fn
        return fn
    return decorate


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
    try:
        webhook_secret = decrypt_secret(p.stripe_webhook_secret)
    except RuntimeError as e:
        log.error("stripe webhook secret decrypt failed for %s: %s", slug, e)
        raise HTTPException(status_code=503, detail="webhook secret unreadable") from e

    payload = await request.body()
    try:
        event = stripe.Webhook.construct_event(payload, stripe_signature, webhook_secret)
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

    handler = _HANDLERS.get(event_type)
    if handler is None:
        log.info("ignored stripe event for %s: %s", slug, event_type)
    else:
        handler(db, p, event)

    db.commit()
    return {"received": True, "type": event_type, "product": slug}


@stripe_handler("invoice.paid")
def _on_invoice_paid(db: Session, product: Product, event: dict) -> None:
    obj = event["data"]["object"]
    _extend_or_create(
        db, product=product,
        customer_id=obj.get("customer"),
        email=obj.get("customer_email"),
    )


@stripe_handler("invoice.payment_failed")
def _on_invoice_failed(db: Session, product: Product, event: dict) -> None:
    obj = event["data"]["object"]
    _mark_status(
        db, product=product,
        customer_id=obj.get("customer"),
        status="delinquent", note=event["type"],
    )


@stripe_handler("customer.subscription.deleted")
def _on_subscription_deleted(db: Session, product: Product, event: dict) -> None:
    obj = event["data"]["object"]
    _mark_status(
        db, product=product,
        customer_id=obj.get("customer"),
        status="revoked", note=event["type"],
    )


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
