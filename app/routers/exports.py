"""CSV exports for the admin (Bearer-authenticated).

Three endpoints, all gated by ADMIN_TOKEN:
  GET /v1/admin/exports/customers.csv
  GET /v1/admin/exports/products/<slug>/licenses.csv
  GET /v1/admin/exports/products/<slug>/events.csv

Streamed (StreamingResponse with a generator) so a 10k-row table doesn't
buffer in memory. RFC 4180-style quoting via the stdlib `csv` module.

Why not the cursor-paginated JSON endpoints already in app.routers.api?
- CSV is what Stripe / accounting / a one-off spreadsheet wants.
- Streamed bulk export sidesteps the "200 rows per page" paging dance
  for a one-shot snapshot.

This module is HTTP plumbing only -- the actual queries live in the
service layer or are simple one-liners here when the existing services
don't cover the shape.
"""
from __future__ import annotations

import csv
import io
import logging
from collections.abc import Iterator

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Customer, Event, License
from app.routers.api import _require_admin
from app.services import products as products_svc
from app.services.errors import NotFound

log = logging.getLogger("license-server.exports")

router = APIRouter(prefix="/v1/admin/exports", dependencies=[Depends(_require_admin)])

_UNSAFE_PREFIX: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(v: str) -> str:
    """Spreadsheet-formula guard. Excel/LibreOffice interpret a cell starting
    with `=`, `+`, `-`, `@`, TAB, or CR as a formula and execute it; prefixing
    with a single apostrophe is the canonical neutralisation.

    Applied to every cell emitted by every CSV export so a malicious customer
    name / email / payload that lands in the DB can't fire a formula when the
    admin opens the file."""
    if v and v[0] in _UNSAFE_PREFIX:
        return "'" + v
    return v


def _csv_stream(header: list[str], rows: Iterator[list[str]]) -> Iterator[bytes]:
    """Yield CSV bytes in chunks. One buffer reused across rows so we never
    hold the whole file in memory. Every data cell is run through `_csv_safe`
    so a value starting with a formula character is neutralised."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    yield buf.getvalue().encode("utf-8")
    buf.seek(0)
    buf.truncate(0)
    for row in rows:
        writer.writerow([_csv_safe(cell) for cell in row])
        yield buf.getvalue().encode("utf-8")
        buf.seek(0)
        buf.truncate(0)


def _streaming_csv(filename: str, header: list[str], rows: Iterator[list[str]]) -> StreamingResponse:
    return StreamingResponse(
        _csv_stream(header, rows),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _iso(dt) -> str:
    return dt.isoformat() if dt is not None else ""


@router.get("/customers.csv")
def export_customers(db: Session = Depends(get_db)) -> StreamingResponse:
    """All customers across all products. One row per customer.

    Stripe-customer-id is included so the operator can cross-reference
    against a Stripe export. license_count is computed cheap enough to
    add (single GROUP BY)."""
    rows_q = (
        db.query(Customer)
        .order_by(Customer.created_at.desc(), Customer.id.desc())
        .yield_per(500)
    )

    def gen() -> Iterator[list[str]]:
        for c in rows_q:
            yield [
                c.id,
                c.email,
                c.name or "",
                c.stripe_customer_id or "",
                str(len(c.licenses)) if hasattr(c, "licenses") else "",
                _iso(c.created_at),
            ]

    return _streaming_csv(
        "customers.csv",
        ["id", "email", "name", "stripe_customer_id", "license_count", "created_at"],
        gen(),
    )


@router.get("/products/{slug}/licenses.csv")
def export_licenses(slug: str, db: Session = Depends(get_db)) -> StreamingResponse:
    """All licenses for one product. The most common export -- typical use:
    cross-reference paid customers in the admin UI with Stripe."""
    try:
        p = products_svc.get_product(db, slug)
    except NotFound as e:
        raise HTTPException(status_code=404, detail="product not found") from e
    rows_q = (
        db.query(License)
        .filter_by(product_id=p.id)
        .order_by(License.created_at.desc(), License.id.desc())
        .yield_per(500)
    )

    def gen() -> Iterator[list[str]]:
        for r in rows_q:
            yield [
                r.id, r.key, r.plan, r.status, str(r.max_users),
                _iso(r.valid_until),
                r.customer.email if r.customer else "",
                r.customer.name if (r.customer and r.customer.name) else "",
                r.webhook_url or "",
                _iso(r.created_at),
            ]

    return _streaming_csv(
        f"{slug}-licenses.csv",
        [
            "id", "key", "plan", "status", "max_users", "valid_until",
            "customer_email", "customer_name", "webhook_url", "created_at",
        ],
        gen(),
    )


@router.get("/products/{slug}/events.csv")
def export_events(slug: str, db: Session = Depends(get_db)) -> StreamingResponse:
    """Audit-trail export. Useful for compliance asks (`show me everything
    that happened to license X`) and for offline analytics on heartbeat
    cadence."""
    try:
        p = products_svc.get_product(db, slug)
    except NotFound as e:
        raise HTTPException(status_code=404, detail="product not found") from e
    rows_q = (
        db.query(Event)
        .filter_by(product_id=p.id)
        .order_by(Event.created_at.desc(), Event.id.desc())
        .yield_per(500)
    )
    import json as _json

    def gen() -> Iterator[list[str]]:
        for ev in rows_q:
            yield [
                ev.id,
                _iso(ev.created_at),
                ev.type,
                ev.subject_kind or "",
                ev.subject_id or "",
                ev.license_id or "",
                _json.dumps(ev.payload or {}, separators=(",", ":")),
                ev.note or "",
            ]

    return _streaming_csv(
        f"{slug}-events.csv",
        [
            "id", "created_at", "type", "subject_kind", "subject_id",
            "license_id", "payload", "note",
        ],
        gen(),
    )
