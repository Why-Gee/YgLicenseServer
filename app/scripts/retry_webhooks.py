"""Drain pending webhook deliveries that are due for retry.

Run with:
    python -m app.scripts.retry_webhooks [--limit N]

Picks rows from `webhook_deliveries` where status='pending' and
next_attempt_at <= now, walks each through one HTTP attempt via
`app.webhooks.try_deliver`, and commits. Backoff schedule + abandon
threshold live in app.webhooks; this runner just iterates.

A systemd timer fires this every 5 minutes on the VM. Single-process
flush: if a delivery fails again the row's next_attempt_at gets pushed
out and the next timer tick picks it up.
"""
from __future__ import annotations

import argparse
import logging
import sys

from app._time import utcnow
from app.db import SessionLocal
from app.models import WebhookDelivery
from app.webhooks import try_deliver

log = logging.getLogger("license-server.retry-webhooks")


def run(limit: int = 200) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    db = SessionLocal()
    try:
        now = utcnow()
        pending = (
            db.query(WebhookDelivery)
            .filter(
                WebhookDelivery.status == "pending",
                WebhookDelivery.next_attempt_at <= now,
            )
            .order_by(WebhookDelivery.next_attempt_at)
            .limit(limit)
            .all()
        )
        log.info("found %d pending delivery(ies) due for retry", len(pending))
        delivered = 0
        for d in pending:
            ok = try_deliver(db, d.id)
            db.commit()
            if ok:
                delivered += 1
        log.info("done: %d delivered, %d still pending or abandoned", delivered, len(pending) - delivered)
        return 0
    except Exception:
        db.rollback()
        log.exception("retry pass failed; rolled back")
        return 1
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--limit", type=int, default=200,
        help="Max rows to attempt this pass (default 200).",
    )
    args = parser.parse_args()
    sys.exit(run(limit=args.limit))


if __name__ == "__main__":
    main()
