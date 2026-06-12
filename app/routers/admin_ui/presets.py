"""Feature-preset management: list, create, edit, single + bulk delete.

Presets are pure authoring templates for license `features` keys (see
app.services.presets). One page manages both scopes: global (every product)
and per-product.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import FeaturePreset, Product
from app.routers.admin_ui._deps import err_code, require_csrf, require_login, templates
from app.services import presets as presets_svc
from app.services.errors import Conflict, NotFound, ValidationFailed

router = APIRouter()


@router.get("/admin/presets", response_class=HTMLResponse)
def presets_page(request: Request, db: Session = Depends(get_db)) -> Response:
    require_login(request)
    presets = presets_svc.list_presets(db)
    products = db.query(Product).order_by(Product.slug.asc()).all()
    return templates.TemplateResponse(
        request, "presets.html",
        {"presets": presets, "products": products},
    )


@router.post("/admin/presets")
def preset_create(
    request: Request,
    product_id: str = Form(""),
    # Default-empty (not Form(...)) so an empty submit gets the friendly
    # ?error= redirect from service validation instead of a JSON 422.
    key: str = Form(""),
    value_type: str = Form(""),
    default_value: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    try:
        presets_svc.create_preset(
            db,
            product_id=product_id.strip() or None,
            key=key, value_type=value_type, default_raw=default_value,
            note="ui/preset-create",
        )
    except NotFound as e:
        raise HTTPException(status_code=404) from e
    except (ValidationFailed, Conflict) as e:
        return RedirectResponse(f"/admin/presets?error={err_code(e)}", status_code=303)
    return RedirectResponse("/admin/presets?created=1", status_code=303)


@router.post("/admin/presets/{pid}/edit")
def preset_edit(
    pid: str,
    request: Request,
    key: str = Form(""),
    value_type: str = Form(""),
    default_value: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    preset = db.get(FeaturePreset, pid)
    if preset is None:
        raise HTTPException(status_code=404)
    try:
        presets_svc.update_preset(
            db, preset,
            key=key, value_type=value_type, default_raw=default_value,
            note="ui/preset-edit",
        )
    except (ValidationFailed, Conflict) as e:
        return RedirectResponse(f"/admin/presets?error={err_code(e)}", status_code=303)
    return RedirectResponse("/admin/presets?edited=1", status_code=303)


@router.post("/admin/presets/{pid}/delete")
def preset_delete_one(
    pid: str, request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    preset = db.get(FeaturePreset, pid)
    if preset is None:
        raise HTTPException(status_code=404)
    presets_svc.delete_presets(db, [preset], note="ui/preset-delete")
    return RedirectResponse("/admin/presets?deleted=1", status_code=303)


@router.post("/admin/presets/delete")
def presets_bulk_delete(
    request: Request,
    preset_ids: list[str] = Form(default=[]),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    if not preset_ids:
        return RedirectResponse("/admin/presets?error=no+presets+selected", status_code=303)
    rows = (
        db.query(FeaturePreset).filter(FeaturePreset.id.in_(preset_ids)).all()
    )
    n = presets_svc.delete_presets(db, rows, note="ui/preset-bulk-delete")
    return RedirectResponse(f"/admin/presets?deleted={n}", status_code=303)
