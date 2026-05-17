"""Product CRUD: list, new form, create, single + bulk delete, detail,
public-key download."""
from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import License
from app.routers.admin_ui._deps import err_code, require_csrf, require_login, templates
from app.services import products as products_svc
from app.services.errors import Conflict, NotFound

router = APIRouter()


@router.get("/admin/products", response_class=HTMLResponse)
def products_list(request: Request, db: Session = Depends(get_db)) -> Response:
    """Full products listing — moved out of the dashboard in v0.7.1."""
    require_login(request)
    products = products_svc.list_products(db)
    return templates.TemplateResponse(request, "products.html", {"products": products})


@router.get("/admin/products/new", response_class=HTMLResponse)
def product_new_form(request: Request) -> Response:
    require_login(request)
    return templates.TemplateResponse(request, "product_new.html")


@router.post("/admin/products")
def product_create(
    request: Request,
    slug: str = Form(...),
    name: str = Form(...),
    key_prefix: str = Form(...),
    description: str = Form(""),
    jwt_issuer: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    try:
        products_svc.create_product(
            db, slug=slug, name=name, key_prefix=key_prefix,
            description=description or None,
            jwt_issuer=jwt_issuer or None,
        )
    except Conflict as e:
        return RedirectResponse(
            f"/admin/products/new?error={err_code(e)}", status_code=303
        )
    return RedirectResponse(f"/admin/products/{slug}", status_code=303)


@router.post("/admin/products/{slug}/delete")
def product_delete_one(
    slug: str, request: Request, bg: BackgroundTasks,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Single-row delete (trash-icon path)."""
    require_login(request)
    require_csrf(request, csrf_token)
    try:
        result = products_svc.delete_product(db, slug)
    except NotFound as e:
        raise HTTPException(status_code=404) from e
    return RedirectResponse(
        f"/admin?deleted_products=1&deleted_licenses={result.license_count}",
        status_code=303,
    )


@router.post("/admin/products/delete")
def products_bulk_delete(
    request: Request,
    bg: BackgroundTasks,
    product_slugs: list[str] = Form(default=[]),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    if not product_slugs:
        return RedirectResponse("/admin?error=no+products+selected", status_code=303)
    deleted_products = 0
    deleted_licenses = 0
    for slug in product_slugs:
        try:
            result = products_svc.delete_product(db, slug)
        except NotFound:
            continue
        deleted_licenses += result.license_count
        deleted_products += 1
    return RedirectResponse(
        f"/admin?deleted_products={deleted_products}&deleted_licenses={deleted_licenses}",
        status_code=303,
    )


@router.get("/admin/products/{slug}", response_class=HTMLResponse)
def product_detail(slug: str, request: Request, db: Session = Depends(get_db)) -> Response:
    require_login(request)
    try:
        p = products_svc.get_product(db, slug)
    except NotFound as e:
        raise HTTPException(status_code=404) from e
    licenses = (
        db.query(License)
        .filter_by(product_id=p.id)
        .order_by(License.created_at.desc())
        .limit(200)
        .all()
    )
    return templates.TemplateResponse(
        request, "product_detail.html",
        {"product": p, "licenses": licenses},
    )


@router.get("/admin/products/{slug}/pubkey.pem", response_class=PlainTextResponse)
def product_pubkey_download(
    slug: str, request: Request, db: Session = Depends(get_db)
) -> Response:
    require_login(request)
    try:
        p = products_svc.get_product(db, slug)
    except NotFound as e:
        raise HTTPException(status_code=404) from e
    return PlainTextResponse(
        p.public_key_pem,
        headers={"Content-Disposition": f'attachment; filename="{slug}_pub.pem"'},
    )
