"""Product CRUD: list, create, edit, single + bulk delete, detail,
public-key download."""
from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import License
from app.routers.admin_ui._deps import err_code, require_csrf, require_login, templates
from app.services import products as products_svc
from app.services.errors import Conflict, NotFound, ValidationFailed

router = APIRouter()


@router.get("/admin/products", response_class=HTMLResponse)
def products_list(request: Request, db: Session = Depends(get_db)) -> Response:
    """Full products listing — moved out of the dashboard in v0.7.1.

    Counts are joined in a single aggregate query (not derived from
    `p.licenses` in the template, which would trip N+1 lazy-loads)."""
    require_login(request)
    pairs = products_svc.list_products_with_counts(db)
    products = [p for p, _ in pairs]
    license_counts = {p.id: n for p, n in pairs}
    return templates.TemplateResponse(
        request, "products.html",
        {"products": products, "license_counts": license_counts},
    )


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
            validate_format=True,
        )
    except (Conflict, ValidationFailed) as e:
        return RedirectResponse(
            f"/admin/products?error={err_code(e)}", status_code=303,
        )
    return RedirectResponse(f"/admin/products/{slug}", status_code=303)


@router.post("/admin/products/{slug}/edit")
def product_edit(
    slug: str,
    request: Request,
    new_slug: str = Form("", alias="slug"),
    name: str = Form(""),
    key_prefix: str = Form(""),
    jwt_issuer: str = Form(""),
    description: str = Form(""),
    return_to: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Edit an existing product via the unified create/edit modal.

    The modal always submits all five fields. Empty values are forwarded as-is;
    the service interprets "" as 'clear/default' per field (NULL for
    description, default-derived for jwt_issuer, error for required fields).

    return_to controls the post-edit redirect target so the admin lands back
    where they were:
      - "detail" -> /admin/products/<slug>?product_edited=1 (and on error,
        back to the same detail page with ?error=<code>). Used by the modal
        included on product_detail.html.
      - anything else (incl. "list" or "") -> /admin/products?product_edited=
        <slug> on success, /admin/products?error=<code> on error. Used by
        the modal on the products listing page.
    """
    require_login(request)
    require_csrf(request, csrf_token)
    to_detail = return_to == "detail"
    try:
        p = products_svc.update_product(
            db, slug,
            new_slug=new_slug,
            name=name,
            key_prefix=key_prefix,
            jwt_issuer=jwt_issuer,
            description=description,
        )
    except NotFound as e:
        raise HTTPException(status_code=404) from e
    except (Conflict, ValidationFailed) as e:
        # Error path: slug didn't change, so the original detail URL is still
        # valid. Send the admin back there with the error code.
        if to_detail:
            return RedirectResponse(
                f"/admin/products/{slug}?error={err_code(e)}", status_code=303,
            )
        return RedirectResponse(
            f"/admin/products?error={err_code(e)}", status_code=303,
        )
    if to_detail:
        return RedirectResponse(
            f"/admin/products/{p.slug}?product_edited=1", status_code=303,
        )
    return RedirectResponse(
        f"/admin/products?product_edited={p.slug}", status_code=303,
    )


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
        result = products_svc.delete_product(db, slug, schedule=bg.add_task)
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
    # Per-product is its own transaction (each delete_product commits once).
    # Cross-product bulk is rare and a same-tx batch would hold locks on all
    # licenses of every selected product simultaneously, so we keep these
    # independent. NotFound skips that one slug without aborting the rest.
    deleted_products = 0
    deleted_licenses = 0
    for slug in product_slugs:
        try:
            result = products_svc.delete_product(db, slug, schedule=bg.add_task)
        except NotFound:
            continue
        deleted_licenses += result.license_count
        deleted_products += 1
    return RedirectResponse(
        f"/admin?deleted_products={deleted_products}&deleted_licenses={deleted_licenses}",
        status_code=303,
    )


@router.get("/admin/products/{slug}", response_class=HTMLResponse)
def product_detail(
    slug: str,
    request: Request,
    cursor: str | None = None,
    db: Session = Depends(get_db),
) -> Response:
    """Cursor-paginated license list. Page size fixed at DEFAULT_LIMIT; if
    the product has more licenses than that, the template renders a Next
    link. The previous 200-row hard cap silently dropped any older rows --
    cursor pagination exposes them properly."""
    require_login(request)
    from app.pagination import DEFAULT_LIMIT, paginate
    try:
        p = products_svc.get_product(db, slug)
    except NotFound as e:
        raise HTTPException(status_code=404) from e
    base = (
        db.query(License)
        .filter_by(product_id=p.id)
        .order_by(License.created_at.desc(), License.id.desc())
    )
    page = paginate(
        base, cursor_col=(License.created_at, License.id),
        cursor=cursor, limit=DEFAULT_LIMIT,
    )
    from app.services import presets as presets_svc
    return templates.TemplateResponse(
        request, "product_detail.html",
        {
            "product": p, "licenses": page.items, "next_cursor": page.next_cursor,
            # Global + this product's presets, for the license modal's
            # features editor picker.
            "feature_presets": presets_svc.presets_for_product(db, p.id),
        },
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
