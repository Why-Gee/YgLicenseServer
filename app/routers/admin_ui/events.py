"""Events log: HTML list + CSV export."""
from __future__ import annotations

import csv
import io
import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Event
from app.routers.admin_ui._deps import require_login, templates, utcnow

router = APIRouter()


@router.get("/admin/events", response_class=HTMLResponse)
def events_list(request: Request, db: Session = Depends(get_db)) -> Response:
    require_login(request)
    rows = db.query(Event).order_by(Event.created_at.desc()).limit(500).all()
    return templates.TemplateResponse(request, "events.html", {"events": rows})


@router.get("/admin/events.csv")
def events_csv(request: Request, db: Session = Depends(get_db)) -> Response:
    """Export the events log (most-recent 5000 rows) as CSV. Browser shows
    the OS Save As dialog because of the attachment Content-Disposition."""
    require_login(request)
    rows = db.query(Event).order_by(Event.created_at.desc()).limit(5000).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["when", "type", "license_id", "product_id", "note", "payload"])
    for e in rows:
        payload = json.dumps(e.payload or {}, separators=(",", ":"))
        w.writerow([
            e.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            e.type,
            e.license_id or "",
            e.product_id or "",
            e.note or "",
            payload,
        ])
    filename = f"events-{utcnow().strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(
        buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
