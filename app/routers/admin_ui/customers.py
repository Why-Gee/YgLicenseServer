"""Customer list + edit."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Customer
from app.routers.admin_ui._deps import err_code, require_csrf, require_login, templates
from app.services import customers as customers_svc
from app.services.errors import Conflict, NotFound, ValidationFailed

router = APIRouter()


@router.get("/admin/customers", response_class=HTMLResponse)
def customers_list(request: Request, db: Session = Depends(get_db)) -> Response:
    require_login(request)
    rows = db.query(Customer).order_by(Customer.created_at.desc()).all()
    # Per-customer product slugs derived from their licenses. Distinct + sorted
    # so the column reads deterministically and sortable-header text sort
    # works as expected.
    products_by_customer: dict[str, list[str]] = {
        c.id: sorted({lic.product.slug for lic in c.licenses if lic.product})
        for c in rows
    }
    return templates.TemplateResponse(
        request, "customers.html",
        {"customers": rows, "products_by_customer": products_by_customer},
    )


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
