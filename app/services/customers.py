"""Customer-side mutations. Read-paths stay in the routers (they're trivial
joins). The only mutation is edit, which has the dedupe-collision check."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import Customer, Event
from app.services.errors import Conflict, NotFound, ValidationFailed


def edit_customer(
    db: Session, customer_id: str, *,
    email: str,
    name: str = "",
    stripe_customer_id: str = "",
    note: str = "service/customer-edit",
) -> Customer:
    """Update a customer's email/name/stripe_customer_id.

    Email is the natural-key for issuance dedupe; changing it to one already
    owned by another customer is rejected via `Conflict`. Empty email raises
    `ValidationFailed`.
    """
    cust = db.query(Customer).filter_by(id=customer_id).one_or_none()
    if cust is None:
        raise NotFound("customer not found")
    new_email = email.strip()
    if not new_email:
        raise ValidationFailed("email required")
    if new_email != cust.email:
        clash = (
            db.query(Customer)
            .filter(Customer.email == new_email, Customer.id != customer_id)
            .one_or_none()
        )
        if clash is not None:
            raise Conflict("email already used by another customer")
    cust.email = new_email
    cust.name = name.strip() or None
    cust.stripe_customer_id = stripe_customer_id.strip() or None
    db.add(Event(
        type="customer:edited",
        payload={"customer_id": cust.id, "email": cust.email},
        note=note,
    ))
    db.commit()
    return cust
