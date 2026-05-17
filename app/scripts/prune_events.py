"""Prune old `heartbeat` events from the `events` table.

Run with:
    python -m app.scripts.prune_events [--older-than-days N] [--dry-run]
    python -m app.scripts.prune_events --types heartbeat,foo [--older-than-days N]

What it does:
- Counts and deletes rows from `events` where `type` is in the prune set
  AND `created_at < now - N days`. Default prune set is just `heartbeat`;
  default age threshold is 90 days.
- Preserves every other event type forever -- `issued`, `status:*`,
  `license:*`, `customer:*`, `webhook:*`, `extended`, etc. are
  audit-relevant and stay.

Why this exists:
- Every `/v1/check` writes one `heartbeat` row. At 1000 installs/day
  that's 365k rows/year per product; SQLite happily handles it but the
  `/admin/events/<product>` pages get slow and the backups get fat.
- A surgical Python prune lets us iterate (e.g. add archival to GCS
  later) without burying logic in an ON DELETE CASCADE.

Safety:
- `--dry-run` reports the COUNT it would delete without touching anything.
- Single transaction; mid-loop failure rolls back the entire batch.
- Refuses to operate on the empty type set (would be a foot-gun).
- Refuses on `--older-than-days 0` (would prune everything matching the
  type filter, including events from the same second).
"""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import timedelta

from app._time import utcnow
from app.db import SessionLocal
from app.models import Event

log = logging.getLogger("license-server.prune-events")

DEFAULT_TYPES = ("heartbeat",)
DEFAULT_OLDER_THAN_DAYS = 90


def run(
    older_than_days: int = DEFAULT_OLDER_THAN_DAYS,
    types: tuple[str, ...] = DEFAULT_TYPES,
    dry_run: bool = False,
) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if older_than_days <= 0:
        log.error("--older-than-days must be >= 1 (got %d)", older_than_days)
        return 2
    if not types:
        log.error("at least one event type must be specified")
        return 2

    cutoff = utcnow() - timedelta(days=older_than_days)
    log.info(
        "prune target: type in %s, created_at < %s%s",
        list(types), cutoff.isoformat(), " (DRY RUN)" if dry_run else "",
    )

    db = SessionLocal()
    try:
        q = db.query(Event).filter(Event.type.in_(types), Event.created_at < cutoff)
        count = q.count()
        log.info("matched %d row(s)", count)
        if count == 0 or dry_run:
            return 0
        deleted = q.delete(synchronize_session=False)
        db.commit()
        log.info("deleted %d row(s)", deleted)
        return 0
    except Exception:
        db.rollback()
        log.exception("prune failed; rolled back")
        return 1
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--older-than-days", type=int, default=DEFAULT_OLDER_THAN_DAYS,
        help=f"Delete events older than this (default {DEFAULT_OLDER_THAN_DAYS}).",
    )
    parser.add_argument(
        "--types", default=",".join(DEFAULT_TYPES),
        help=(
            f"Comma-separated event types to prune (default {','.join(DEFAULT_TYPES)}). "
            "Other types are NEVER touched."
        ),
    )
    parser.add_argument("--dry-run", action="store_true", help="Count, don't delete.")
    args = parser.parse_args()
    types = tuple(t.strip() for t in args.types.split(",") if t.strip())
    sys.exit(run(older_than_days=args.older_than_days, types=types, dry_run=args.dry_run))


if __name__ == "__main__":
    main()
