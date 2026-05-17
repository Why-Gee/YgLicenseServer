"""One-shot KEK rewrap for product secrets.

Run with:
    python -m app.scripts.rewrap_secrets [--dry-run]

What it does:
- Reads every row from `products`.
- For each of `private_key_pem`, `stripe_webhook_secret`, `stripe_api_key`,
  if the value is plaintext (no `enc:v1:` prefix), re-encrypts it under the
  currently-configured `LICENSE_KEY_ENCRYPTION_KEY`.
- Already-encrypted values are left untouched (the `is_encrypted` guard
  makes this idempotent).

Why this exists:
- The 8a336b18bca1 Alembic migration runs the same rewrap loop, but only
  ONCE -- when the schema transitions from 9a9f5b6937d8 to 8a336b18bca1. If
  the KEK wasn't configured at that moment (typical on a deploy that adopts
  encryption AFTER the schema migration ran), the rows stay plaintext
  forever, because the keystore doesn't lazy-rewrap on read (a read-time
  rewrite would silently mutate the DB under the request handler, which is
  worse than leaving the rows plaintext).

When to use:
- After setting `LICENSE_KEY_ENCRYPTION_KEY` in env on a deploy that
  previously ran without it.
- After rotating the KEK to a new value: first decrypt under the OLD KEK
  (run with KEY set to the old one + flip `is_encrypted` semantics manually),
  then run again with the NEW KEK. The two-step pattern is left to a
  follow-up; for the common case (plaintext -> first encrypt), this script
  is enough.

Safety:
- Refuses to run if `LICENSE_KEY_ENCRYPTION_KEY` is unset (would be a no-op
  AND mask the misconfig).
- `--dry-run` prints what it would change without touching the DB. Use this
  in prod first.
- Wraps the whole loop in a single transaction. A mid-loop failure rolls
  back the entire batch.
"""
from __future__ import annotations

import argparse
import logging
import sys

from app.config import get_settings
from app.db import SessionLocal
from app.keystore import encrypt_secret, is_encrypted
from app.models import Product

log = logging.getLogger("license-server.rewrap")


def _rewrap_field(value: str | None) -> tuple[str | None, bool]:
    """Returns (new_value, changed). None passes through. Already-encrypted
    values pass through unchanged. Plaintext values come back wrapped."""
    if value is None:
        return None, False
    if is_encrypted(value):
        return value, False
    return encrypt_secret(value), True


def run(dry_run: bool = False) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    s = get_settings()
    if not s.key_encryption_key:
        log.error(
            "LICENSE_KEY_ENCRYPTION_KEY is unset. Cannot rewrap -- set the "
            "KEK in env first, then re-run this command."
        )
        return 2  # EX_USAGE-ish

    db = SessionLocal()
    try:
        products = db.query(Product).all()
        log.info(
            "found %d product row(s) -- scanning for plaintext secrets%s",
            len(products),
            " (DRY RUN, no writes)" if dry_run else "",
        )
        total_changed = 0
        for p in products:
            new_priv, priv_changed = _rewrap_field(p.private_key_pem)
            new_ws, ws_changed = _rewrap_field(p.stripe_webhook_secret)
            new_ak, ak_changed = _rewrap_field(p.stripe_api_key)
            changes = []
            if priv_changed:
                changes.append("private_key_pem")
            if ws_changed:
                changes.append("stripe_webhook_secret")
            if ak_changed:
                changes.append("stripe_api_key")
            if not changes:
                log.info("  %s: all fields already encrypted", p.slug)
                continue
            log.info("  %s: will encrypt %s", p.slug, ", ".join(changes))
            if not dry_run:
                p.private_key_pem = new_priv
                p.stripe_webhook_secret = new_ws
                p.stripe_api_key = new_ak
                total_changed += 1
        if dry_run:
            log.info("dry-run finished. Re-run without --dry-run to apply.")
            return 0
        if total_changed == 0:
            log.info("no rows needed rewrapping. Nothing committed.")
            return 0
        db.commit()
        log.info("committed: %d product row(s) updated", total_changed)
        return 0
    except Exception:
        db.rollback()
        log.exception("rewrap failed; rolled back")
        return 1
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would change without writing.",
    )
    args = parser.parse_args()
    sys.exit(run(dry_run=args.dry_run))


if __name__ == "__main__":
    main()
