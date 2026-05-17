"""Customer-side reads + mutations. Reads ride aggregate joins so list views
don't trip the lazy-load N+1 on `c.licenses`. The only mutation is edit,
which has the dedupe-collision check."""
from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Customer, Event, License
from app.services.errors import Conflict, NotFound, ValidationFailed


def _base_customers_with_counts_query(db: Session):
    """Shared base for the with-counts views. Orders by (created_at, id)
    desc so the pagination keyset has a stable composite key."""
    return (
        db.query(Customer, func.count(License.id))
        .outerjoin(License, License.customer_id == Customer.id)
        .group_by(Customer.id)
        .order_by(Customer.created_at.desc(), Customer.id.desc())
    )


def list_customers_with_counts(db: Session) -> list[tuple[Customer, int]]:
    """Unpaginated list. Kept for tests + internal helpers that genuinely
    need every row (e.g. dashboard total). Endpoints serving HTTP MUST use
    `page_customers_with_counts` instead."""
    return [(c, int(n)) for c, n in _base_customers_with_counts_query(db).all()]


def page_customers_with_counts(
    db: Session, *, cursor: str | None, limit: int,
) -> tuple[list[tuple[Customer, int]], str | None]:
    """Cursor-paginated variant. Returns (items, next_cursor). `next_cursor`
    is None when the result set is exhausted."""
    from app.pagination import paginate

    page = paginate(
        _base_customers_with_counts_query(db),
        cursor_col=(Customer.created_at, Customer.id),
        cursor=cursor, limit=limit,
        # Row shape is (Customer, count) -- pull keys off the entity at row[0].
        key_fn=lambda row: (row[0].created_at, row[0].id),
    )
    items = [(c, int(n)) for c, n in page.items]
    return items, page.next_cursor


def list_customers_with_product_slugs(
    db: Session, *, cursor: str | None = None, limit: int | None = None,
) -> tuple[list[tuple[Customer, int, list[str]]], str | None]:
    """List customers with their license count + sorted set of product slugs.

    Two queries when paginating:
      1) The Customer page with license counts (keyset cursor + LIMIT).
      2) DISTINCT product slugs for the customer ids on this page only.

    Returns (rows, next_cursor). `limit=None` returns everything in one shot
    (and next_cursor is always None) -- used by tests that need the full set.
    """
    from app.models import Product
    from app.pagination import DEFAULT_LIMIT, paginate

    if limit is None:
        # Unpaginated path -- one query, single join. Old behaviour for
        # callers that legitimately want the whole list.
        rows = (
            db.query(Customer, License.id, Product.slug)
            .outerjoin(License, License.customer_id == Customer.id)
            .outerjoin(Product, Product.id == License.product_id)
            .order_by(Customer.created_at.desc(), Customer.id.desc(), Product.slug)
            .all()
        )
        return _bucket_customer_slugs(rows), None

    # Paginated path: get the customer page, then fetch slugs only for
    # those ids. Keeps the per-page work bounded.
    page = paginate(
        _base_customers_with_counts_query(db),
        cursor_col=(Customer.created_at, Customer.id),
        cursor=cursor, limit=limit or DEFAULT_LIMIT,
    )
    if not page.items:
        return [], None
    cust_count: dict[str, tuple[Customer, int]] = {c.id: (c, int(n)) for c, n in page.items}
    slug_rows = (
        db.query(License.customer_id, Product.slug)
        .join(Product, Product.id == License.product_id)
        .filter(License.customer_id.in_(cust_count.keys()))
        .all()
    )
    slugs_by_cid: dict[str, set[str]] = {}
    for cid, slug in slug_rows:
        slugs_by_cid.setdefault(cid, set()).add(slug)
    # Preserve the page's order (already by created_at/id desc).
    result = [
        (cust, count, sorted(slugs_by_cid.get(cust.id, set())))
        for cust, count in (cust_count[c.id] for c, _ in page.items)
    ]
    return result, page.next_cursor


def _bucket_customer_slugs(rows) -> list[tuple[Customer, int, list[str]]]:
    """Bucket a (Customer, license_id, slug) flat result into the per-row
    triple shape. Used by the unpaginated path; the paginated path issues
    a separate slug query so it doesn't need this."""
    by_id: dict[str, tuple[Customer, int, set[str]]] = {}
    order: list[Customer] = []
    for c, license_id, slug in rows:
        if c.id not in by_id:
            by_id[c.id] = (c, 0, set())
            order.append(c)
        cust, count, slugs = by_id[c.id]
        if license_id is not None:
            count += 1
        if slug:
            slugs.add(slug)
        by_id[c.id] = (cust, count, slugs)
    return [(by_id[c.id][0], by_id[c.id][1], sorted(by_id[c.id][2])) for c in order]


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
