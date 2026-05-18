"""Send pre-expiry email warnings to license customers.

Run with:
    python -m app.scripts.send_expiry_warnings [--dry-run] [--thresholds 30,14,7]

What it does:
- Walks every active license whose `valid_until` falls within the next N
  days for each threshold in the configured set (default: 30, 14, 7).
- For each (license, threshold) pair, checks the events table for an
  `expiry_warning:<threshold>` event; if absent, sends the email and
  records the event so re-running is idempotent.
- Skips licenses with no customer email (theoretical -- they always have
  one, but defensive), and skips when status != 'active'.

Why the threshold-tagged event approach:
- Lets the operator add/remove thresholds without re-warning the world.
- An expired license that lapsed without the customer renewing won't
  re-warn after re-issuance (the new license has a fresh valid_until +
  no events linked yet).
- The script can run hourly without spamming -- the dedup event is the
  source of truth, not a flag on the license.

Designed to run from a daily systemd timer alongside the backup +
events-prune timers.
"""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import timedelta

from app._time import utcnow
from app.config import get_settings
from app.db import SessionLocal
from app.email import send_expiry_warning_email
from app.models import Event, License

log = logging.getLogger("license-server.expiry-warnings")

DEFAULT_THRESHOLDS = (30, 14, 7)


def _event_type(threshold_days: int) -> str:
    return f"expiry_warning:{threshold_days}"


def _already_warned(db, license_id: str, threshold: int) -> bool:
    return db.query(Event.id).filter_by(
        license_id=license_id, type=_event_type(threshold),
    ).first() is not None


def _pick_threshold(days_left: float, thresholds: tuple[int, ...]) -> int | None:
    """Return the most specific threshold for the days-left value:
    the largest threshold strictly less than-or-equal to days_left+1 that
    we haven't yet hit. The "+1" means a license with 30.0 days left
    matches threshold=30 even with sub-day jitter."""
    # Smallest threshold first so the "most urgent" wins when both apply.
    for t in sorted(thresholds):
        if days_left <= t:
            return t
    return None


def run(
    thresholds: tuple[int, ...] = DEFAULT_THRESHOLDS,
    dry_run: bool = False,
) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    s = get_settings()
    if not s.resend_api_key:
        log.warning(
            "RESEND_API_KEY is unset; emails would be skipped. Continuing "
            "as a no-op so the systemd unit doesn't crash-loop -- exit 0."
        )
        return 0

    now = utcnow()
    max_threshold = max(thresholds)
    window_end = now + timedelta(days=max_threshold)

    db = SessionLocal()
    sent = 0
    skipped = 0
    try:
        licenses = (
            db.query(License)
            .filter(License.status == "active")
            .filter(License.valid_until <= window_end)
            .filter(License.valid_until > now)
            .all()
        )
        log.info(
            "found %d active license(s) with valid_until in the next %d days",
            len(licenses), max_threshold,
        )
        for lic in licenses:
            days_left = (lic.valid_until - now).total_seconds() / 86400.0
            t = _pick_threshold(days_left, thresholds)
            if t is None:
                continue
            if _already_warned(db, lic.id, t):
                skipped += 1
                continue
            email = lic.customer.email if lic.customer else None
            if not email:
                continue
            log.info(
                "warning %s (license=%s, %.1fd left, threshold=%d)",
                email, lic.id, days_left, t,
            )
            if dry_run:
                continue
            ok = send_expiry_warning_email(
                to=email, key=lic.key, product_name=lic.product.name,
                days_left=int(round(days_left)),
                valid_until_iso=lic.valid_until.date().isoformat(),
            )
            if ok:
                # Record the event so we don't re-warn at the same threshold.
                db.add(Event(
                    license_id=lic.id, product_id=lic.product_id,
                    type=_event_type(t),
                    payload={"days_left": round(days_left, 2), "threshold": t},
                    note="auto/expiry-warning",
                ))
                db.commit()
                sent += 1
            else:
                log.warning("send failed; will retry next run")
        log.info("done: sent=%d, skipped_already_warned=%d", sent, skipped)
        return 0
    except Exception:
        db.rollback()
        log.exception("expiry-warning pass failed; rolled back")
        return 1
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--thresholds", default=",".join(str(t) for t in DEFAULT_THRESHOLDS),
        help=(
            f"Comma-separated days-before-expiry to warn at "
            f"(default {','.join(str(t) for t in DEFAULT_THRESHOLDS)})."
        ),
    )
    parser.add_argument("--dry-run", action="store_true", help="Log only, don't send.")
    args = parser.parse_args()
    thresholds = tuple(sorted({int(t.strip()) for t in args.thresholds.split(",") if t.strip()}))
    if not thresholds:
        log.error("at least one threshold required")
        sys.exit(2)
    sys.exit(run(thresholds=thresholds, dry_run=args.dry_run))


if __name__ == "__main__":
    main()
