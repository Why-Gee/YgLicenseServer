"""Backups page: list/download local archives, back-up-now, delete (single +
bulk), restore from an existing archive or an uploaded file (typed-phrase
confirmed). Restore is full-replace — see app.services.backups for the
safety ordering."""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app import backup as bk
from app import backup_s3 as s3
from app.config import get_settings
from app.db import get_db
from app.routers.admin_ui._deps import err_code, require_csrf, require_login, templates
from app.services import backups as backups_svc
from app.services.errors import ValidationFailed

router = APIRouter()

# Uploaded archives stream into memory; the whole DB dump for this server's
# scale is small (license rows, no media), but cap it so a fat-fingered
# upload can't balloon the process.
MAX_UPLOAD_BYTES = 200 * 1024 * 1024


@router.get("/admin/backups", response_class=HTMLResponse)
def backups_page(request: Request, db: Session = Depends(get_db)) -> Response:
    require_login(request)
    s = get_settings()
    return templates.TemplateResponse(
        request, "backups.html",
        {
            "backups": bk.list_local_backups(),
            "backup_dir": str(bk.backup_dir()),
            "s3_enabled": s3.s3_enabled(),
            "s3_bucket": s.backup_s3_bucket,
            "encryption_on": bool(s.key_encryption_key),
            "retention_count": s.backup_retention_count,
            "retention_days": s.backup_retention_days,
            "restore_phrase": backups_svc.RESTORE_PHRASE,
        },
    )


@router.post("/admin/backups/create")
def backup_create(
    request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    result = backups_svc.create_backup(db, note="ui/backup")
    qs = f"created={result.filename}"
    if result.s3_error:
        qs += "&s3_failed=1"
    return RedirectResponse(f"/admin/backups?{qs}", status_code=303)


@router.get("/admin/backups/download/{name}")
def backup_download(name: str, request: Request) -> Response:
    require_login(request)
    try:
        path = bk.safe_backup_path(name)
    except ValidationFailed as e:
        raise HTTPException(status_code=404) from e
    if not path.is_file():
        raise HTTPException(status_code=404)
    return FileResponse(
        path, filename=name, media_type="application/octet-stream",
    )


@router.post("/admin/backups/{name}/restore")
def backup_restore_local(
    name: str,
    request: Request,
    confirmation_phrase: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    try:
        path = bk.safe_backup_path(name)
        if not path.is_file():
            raise HTTPException(status_code=404)
        backups_svc.restore_backup(
            db, path.read_bytes(),
            confirmation_phrase=confirmation_phrase,
            source=f"local:{name}", note="ui/restore",
        )
    except ValidationFailed as e:
        return RedirectResponse(f"/admin/backups?error={err_code(e)}", status_code=303)
    return RedirectResponse("/admin/backups?restored=1", status_code=303)


@router.post("/admin/backups/restore-upload")
async def backup_restore_upload(
    request: Request,
    file: UploadFile = File(...),
    confirmation_phrase: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        return RedirectResponse("/admin/backups?error=backup+too+large", status_code=303)
    try:
        backups_svc.restore_backup(
            db, data,
            confirmation_phrase=confirmation_phrase,
            source=f"upload:{file.filename}", note="ui/restore-upload",
        )
    except ValidationFailed as e:
        return RedirectResponse(f"/admin/backups?error={err_code(e)}", status_code=303)
    return RedirectResponse("/admin/backups?restored=1", status_code=303)


@router.post("/admin/backups/{name}/delete")
def backup_delete_one(
    name: str, request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    try:
        path = bk.safe_backup_path(name)
    except ValidationFailed as e:
        raise HTTPException(status_code=404) from e
    path.unlink(missing_ok=True)
    return RedirectResponse("/admin/backups?deleted=1", status_code=303)


@router.post("/admin/backups/delete")
def backups_bulk_delete(
    request: Request,
    backup_names: list[str] = Form(default=[]),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    if not backup_names:
        return RedirectResponse("/admin/backups?error=no+backups+selected", status_code=303)
    n = 0
    for name in backup_names:
        try:
            path = bk.safe_backup_path(name)
        except ValidationFailed:
            continue  # hostile/garbage name: skip, same as other bulk paths
        if path.is_file():
            path.unlink()
            n += 1
    return RedirectResponse(f"/admin/backups?deleted={n}", status_code=303)
