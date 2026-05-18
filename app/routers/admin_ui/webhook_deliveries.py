"""Webhook deliveries admin page.

Read-only list of the `webhook_deliveries` retry queue with status filters,
plus a per-row "Retry now" button that resets `next_attempt_at` so the
next worker tick (or an immediate sync attempt) picks the row up.

Default view shows the most-recent 200 rows ordered newest-first. A
`?status=pending|delivered|abandoned` query param filters; when unset,
all statuses are shown.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app._time import utcnow
from app.db import get_db
from app.models import WebhookDelivery
from app.routers.admin_ui._deps import require_csrf, require_login, templates
from app.webhooks import attempt_in_fresh_session

router = APIRouter()

_ALLOWED_STATUS = {"pending", "delivered", "abandoned"}


@router.get("/admin/webhook-deliveries", response_class=HTMLResponse)
def list_deliveries(
    request: Request,
    status: str | None = None,
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    status_filter = status if status in _ALLOWED_STATUS else None
    q = db.query(WebhookDelivery).order_by(WebhookDelivery.created_at.desc())
    if status_filter:
        q = q.filter(WebhookDelivery.status == status_filter)
    rows = q.limit(200).all()
    # Counts per status -- gives the operator an at-a-glance "anything
    # stuck?" without scrolling.
    counts = {
        s: db.query(WebhookDelivery).filter_by(status=s).count()
        for s in _ALLOWED_STATUS
    }
    return templates.TemplateResponse(
        request, "webhook_deliveries.html",
        {
            "deliveries": rows,
            "counts": counts,
            "active_status": status_filter,
            "now": utcnow(),
        },
    )


@router.post("/admin/webhook-deliveries/{delivery_id}/retry")
def retry_delivery(
    request: Request,
    delivery_id: str,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Force an immediate retry. Marks the row pending (if abandoned), resets
    next_attempt_at to now, then attempts one send in a fresh session.

    Useful when a receiver-side outage that abandoned a delivery is now
    fixed and the operator wants to redeliver before the next scheduled
    timer tick (or after retry attempts have been exhausted)."""
    require_login(request)
    require_csrf(request, csrf_token)
    d = db.query(WebhookDelivery).filter_by(id=delivery_id).one_or_none()
    if d is None:
        return RedirectResponse(
            "/admin/webhook-deliveries?error=not_found", status_code=303,
        )
    # Allow re-running abandoned deliveries: flip back to pending with a
    # fresh attempt counter so the backoff schedule has room.
    if d.status == "abandoned":
        d.status = "pending"
        d.attempts = 0
    d.next_attempt_at = utcnow()
    d.last_error = None
    db.commit()
    # Fire the attempt synchronously so the admin sees the result reflected
    # on the next page load (success -> delivered, fail -> pending again).
    attempt_in_fresh_session(d.id)
    return RedirectResponse("/admin/webhook-deliveries?retried=1", status_code=303)
