"""Customer list + edit + email-lookup (for the issue-license modal)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Customer
from app.routers.admin_ui._deps import err_code, require_csrf, require_login, templates
from app.services import customers as customers_svc
from app.services.errors import Conflict, NotFound, ValidationFailed

router = APIRouter()


@router.get("/admin/customers", response_class=HTMLResponse)
def customers_list(
    request: Request,
    cursor: str | None = None,
    db: Session = Depends(get_db),
) -> Response:
    """Cursor-paginated. `?cursor=<token>` advances; the template renders a
    Next link when there's more. Page size is fixed at DEFAULT_LIMIT so the
    URL stays clean (the JSON API endpoint exposes `?limit=` for callers
    that need per-page control)."""
    require_login(request)
    from app.pagination import DEFAULT_LIMIT
    triples, next_cursor = customers_svc.list_customers_with_product_slugs(
        db, cursor=cursor, limit=DEFAULT_LIMIT,
    )
    rows = [c for c, _, _ in triples]
    license_counts = {c.id: n for c, n, _ in triples}
    products_by_customer = {c.id: slugs for c, _, slugs in triples}
    return templates.TemplateResponse(
        request, "customers.html",
        {
            "customers": rows,
            "products_by_customer": products_by_customer,
            "license_counts": license_counts,
            "next_cursor": next_cursor,
        },
    )


@router.get("/admin/customers/lookup")
def customer_lookup(
    request: Request,
    email: str,
    db: Session = Depends(get_db),
) -> Response:
    """Email-keyed lookup used by the issue-license modal. The modal calls
    this on email-blur so the admin sees whether the address belongs to an
    existing customer (whose name must not be silently rewritten via the
    license form) or a new one (where the name field is the initial set).

    Cookie-auth like every other /admin/* route. Returns 200 with a small
    JSON envelope -- `exists=false` for a new email, `exists=true` plus the
    persisted name + customer id when the row is already there. The id lets
    the modal link directly to /admin/customers#cid for renames."""
    require_login(request)
    email_clean = email.strip()
    if not email_clean:
        return JSONResponse({"exists": False})
    # Case-insensitive match: emails are case-insensitive per RFC 5321 in
    # practice, and stored values may have mixed case from import paths.
    c = (
        db.query(Customer)
        .filter(Customer.email.ilike(email_clean))
        .one_or_none()
    )
    if c is None:
        return JSONResponse({"exists": False})
    return JSONResponse({
        "exists": True,
        "id": c.id,
        "name": c.name or "",
    })


@router.post("/admin/customers/{cid}/edit")
def customer_edit(
    cid: str,
    request: Request,
    name: str = Form(""),
    email: str = Form(...),
    stripe_customer_id: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Edit a customer's name / email / stripe_customer_id. Email is the
    natural-key used by license issuance dedupe, so changing it to an email
    already owned by another customer is rejected (400 via ?error=)."""
    require_login(request)
    require_csrf(request, csrf_token)
    try:
        cust = customers_svc.edit_customer(
            db, cid, email=email, name=name,
            stripe_customer_id=stripe_customer_id,
            note="ui/customer-edit",
        )
    except NotFound as e:
        raise HTTPException(status_code=404) from e
    except (Conflict, ValidationFailed) as e:
        return RedirectResponse(
            f"/admin/customers?error={err_code(e)}", status_code=303
        )
    return RedirectResponse(f"/admin/customers?edited={cust.id}", status_code=303)
