"""KPI dashboard at /admin."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Customer, Event, License, Product
from app.routers.admin_ui._deps import require_login, templates

router = APIRouter()


@router.get("/admin", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)) -> Response:
    """Counter widgets + Recent Events. The full products list lives at
    /admin/products since v0.7.1; dashboard keeps only the top-level KPIs."""
    require_login(request)
    product_count = db.query(Product).count()
    customer_count = db.query(Customer).count()
    total_licenses = db.query(License).count()
    active_licenses = db.query(License).filter_by(status="active").count()
    recent_events = db.query(Event).order_by(Event.created_at.desc()).limit(20).all()
    return templates.TemplateResponse(
        request, "dashboard.html",
        {
            "product_count": product_count,
            "customer_count": customer_count,
            "total_licenses": total_licenses,
            "active_licenses": active_licenses,
            "recent_events": recent_events,
        },
    )
