"""Backup/restore orchestration: archive creation across destinations,
confirmation-gated full-replace restore with a pre-restore safety snapshot,
audit events. Format/crypto/retention mechanics live in app.backup;
S3 transport in app.backup_s3.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app import backup as bk
from app import backup_s3 as s3
from app.config import get_settings
from app.models import Event
from app.services.errors import ValidationFailed

log = logging.getLogger("license-server.services.backups")

# Typed-phrase gate for restores (ASM-style). Single deployment scope, so a
# fixed phrase: the point is "no accidental click destroys the DB", not
# entropy.
RESTORE_PHRASE = "RESTORE LICENSE SERVER"


@dataclass(frozen=True)
class BackupResult:
    filename: str
    size: int
    encrypted: bool
    s3_key: str | None
    s3_error: str | None


def create_backup(db: Session, *, prefix: str = bk.BACKUP_PREFIX,
                  note: str = "service/backup") -> BackupResult:
    """Export + (maybe) encrypt + write to every configured destination.

    Local write is mandatory and fatal on failure. S3 is best-effort: a
    dead bucket must not kill the nightly job while the local copy is fine
    — the error is logged, surfaced in the result, and recorded on the
    audit event so the admin UI can show it.
    """
    raw = bk.export_archive(db)
    data, encrypted = bk.wrap(raw)
    filename = bk.make_filename(encrypted=encrypted, prefix=prefix)
    (bk.backup_dir() / filename).write_bytes(data)

    s3_key = None
    s3_error = None
    if s3.s3_enabled():
        try:
            s3_key = s3.upload(filename, data)
        except Exception as e:  # boto3 raises many shapes; none should be fatal
            s3_error = f"{type(e).__name__}: {e}"
            log.error("backup S3 upload failed for %s: %s", filename, s3_error)

    db.add(Event(
        type="backup:created",
        payload={
            "file": filename, "size": len(data), "encrypted": encrypted,
            "s3_key": s3_key, "s3_error": s3_error,
        },
        note=note,
    ))
    db.commit()
    return BackupResult(
        filename=filename, size=len(data), encrypted=encrypted,
        s3_key=s3_key, s3_error=s3_error,
    )


def apply_retention() -> dict:
    """Prune scheduled/manual archives per settings on every destination."""
    s = get_settings()
    deleted_local = bk.apply_local_retention(
        keep_count=s.backup_retention_count, max_age_days=s.backup_retention_days,
    )
    deleted_s3: list[str] = []
    if s3.s3_enabled():
        try:
            deleted_s3 = s3.apply_s3_retention(
                keep_count=s.backup_retention_count,
                max_age_days=s.backup_retention_days,
                backup_prefix=bk.BACKUP_PREFIX,
            )
        except Exception as e:
            log.error("S3 retention sweep failed: %s", e)
    return {"local": deleted_local, "s3": deleted_s3}


def restore_backup(
    db: Session, data: bytes, *,
    confirmation_phrase: str,
    source: str,
    note: str = "service/restore",
) -> dict:
    """Confirmation-gated full-replace restore.

    Order of operations is the safety story:
      1. typed phrase must match exactly (no accidental destruction);
      2. archive is parsed + schema-checked BEFORE anything is touched;
      3. the CURRENT state is exported to a local pre-restore_ snapshot
         (never auto-pruned) so a bad restore is one more restore away
         from undone;
      4. wipe + load in one transaction (rollback on any failure).
    """
    if confirmation_phrase.strip() != RESTORE_PHRASE:
        raise ValidationFailed("restore confirmation mismatch")
    manifest = bk.read_manifest(data)  # format + decrypt errors before any write

    safety = create_backup(db, prefix=bk.PRERESTORE_PREFIX, note="service/pre-restore")
    log.info("pre-restore safety snapshot: %s", safety.filename)

    manifest = bk.import_archive(db, data)
    # Written AFTER the wipe+load commit, so it lands in the restored DB.
    db.add(Event(
        type="backup:restored",
        payload={
            "source": source,
            "backup_created_at": manifest.get("created_at"),
            "backup_app_version": manifest.get("app_version"),
            "pre_restore_snapshot": safety.filename,
        },
        note=note,
    ))
    db.commit()
    return manifest
