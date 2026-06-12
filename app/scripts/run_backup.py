"""Scheduled backup runner (systemd timer / cron entrypoint).

Run with:
    python -m app.scripts.run_backup [--no-retention] [--dry-run]

Creates one backup archive (local always; S3 when BACKUP_S3_BUCKET is set),
then applies the retention policy (BACKUP_RETENTION_COUNT /
BACKUP_RETENTION_DAYS) to both destinations. Exit codes: 0 ok, 1 backup
failed, 2 backup ok but S3 upload failed (local copy exists — page-worthy
but not data loss).
"""
from __future__ import annotations

import argparse
import logging
import sys

from app.db import SessionLocal
from app.services import backups as backups_svc

log = logging.getLogger("license-server.run-backup")


def run(*, retention: bool = True, dry_run: bool = False) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if dry_run:
        from app import backup as bk
        from app import backup_s3 as s3
        log.info(
            "dry run: would back up to %s%s, retention keep=%d age=%dd",
            bk.backup_dir(),
            " + s3" if s3.s3_enabled() else "",
            backups_svc.get_settings().backup_retention_count,
            backups_svc.get_settings().backup_retention_days,
        )
        return 0
    db = SessionLocal()
    try:
        result = backups_svc.create_backup(db, note="script/scheduled")
    except Exception:
        log.exception("backup failed")
        return 1
    finally:
        db.close()
    log.info(
        "backup ok: %s (%d bytes, encrypted=%s, s3=%s)",
        result.filename, result.size, result.encrypted,
        result.s3_key or "off",
    )
    if retention:
        deleted = backups_svc.apply_retention()
        if deleted["local"] or deleted["s3"]:
            log.info("retention pruned local=%s s3=%s", deleted["local"], deleted["s3"])
    if result.s3_error:
        log.error("S3 upload failed (local copy OK): %s", result.s3_error)
        return 2
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-retention", action="store_true",
                        help="Skip the retention sweep after the backup.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report destinations + policy, change nothing.")
    args = parser.parse_args()
    sys.exit(run(retention=not args.no_retention, dry_run=args.dry_run))


if __name__ == "__main__":
    main()
