"""One-shot KEK rewrap for product secrets.

Run with:
    python -m app.scripts.rewrap_secrets [--dry-run]
    python -m app.scripts.rewrap_secrets --migrate-from-prev [--dry-run]

Two modes:

1) Default ("first encrypt" + idempotent re-run):
   - Reads every row from `products`.
   - For each of `private_key_pem`, `stripe_webhook_secret`, `stripe_api_key`,
     if the value is plaintext (no `enc:v1:` prefix), encrypts it under
     `LICENSE_KEY_ENCRYPTION_KEY`. Already-encrypted values pass through.
   - Use after first turning on `LICENSE_KEY_ENCRYPTION_KEY` on a deploy
     that previously ran without it.

2) `--migrate-from-prev` (KEK rotation):
   - Reads every row. For each encrypted field, decrypts under
     `LICENSE_KEY_ENCRYPTION_KEY_PREV` and re-encrypts under
     `LICENSE_KEY_ENCRYPTION_KEY`. Plaintext rows go through the default
     "first encrypt" path under the new KEK.
   - After a successful run, the operator removes
     `LICENSE_KEY_ENCRYPTION_KEY_PREV` from the env and redeploys.
   - No-op (and exits 0) when PREV == current.

Why this exists:
- The 8a336b18bca1 Alembic migration runs the default rewrap loop, but only
  ONCE -- when the schema transitions. If the KEK wasn't configured at that
  moment, the rows stay plaintext forever, because the keystore doesn't
  lazy-rewrap on read (a read-time rewrite would silently mutate the DB
  under the request handler, which is worse than leaving rows plaintext).
- Rotating the KEK without PREV migration would brick the deploy --
  encrypted rows become un-decryptable.

Safety:
- Refuses to run if `LICENSE_KEY_ENCRYPTION_KEY` is unset.
- `--migrate-from-prev` refuses to run if PREV is unset.
- `--dry-run` prints intent without touching the DB.
- The whole loop runs in a single transaction; a mid-loop failure rolls
  back the entire batch.
"""
from __future__ import annotations

import argparse
import logging
import sys

from app.config import get_settings
from app.db import SessionLocal
from app.keystore import _decrypt_with, _fernet_prev, encrypt_secret, is_encrypted
from app.models import Product

log = logging.getLogger("license-server.rewrap")


def _rewrap_field(value: str | None) -> tuple[str | None, bool]:
    """Default-mode rewrap: encrypt plaintext under the current KEK. Returns
    (new_value, changed). None passes through. Already-encrypted values
    pass through unchanged."""
    if value is None:
        return None, False
    if is_encrypted(value):
        return value, False
    return encrypt_secret(value), True


def _rewrap_field_migrate(value: str | None, prev) -> tuple[str | None, bool]:
    """KEK-rotation rewrap: decrypt encrypted values under PREV then
    re-encrypt under the current KEK. Plaintext values get encrypted under
    the current KEK (same as the default path)."""
    if value is None:
        return None, False
    if not is_encrypted(value):
        return encrypt_secret(value), True
    plaintext = _decrypt_with(prev, value)
    return encrypt_secret(plaintext), True


def run(dry_run: bool = False, migrate_from_prev: bool = False) -> int:
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

    prev = None
    if migrate_from_prev:
        if not s.key_encryption_key_prev:
            log.error(
                "--migrate-from-prev requires LICENSE_KEY_ENCRYPTION_KEY_PREV "
                "to be set. Aborting."
            )
            return 2
        if s.key_encryption_key_prev == s.key_encryption_key:
            log.info(
                "LICENSE_KEY_ENCRYPTION_KEY_PREV equals current KEK; "
                "nothing to migrate. Exiting."
            )
            return 0
        prev = _fernet_prev()
        if prev is None:
            log.error("LICENSE_KEY_ENCRYPTION_KEY_PREV failed to load; aborting.")
            return 2

    db = SessionLocal()
    try:
        products = db.query(Product).all()
        log.info(
            "found %d product row(s) -- %s%s",
            len(products),
            "rotating from PREV KEK" if migrate_from_prev else "scanning for plaintext secrets",
            " (DRY RUN, no writes)" if dry_run else "",
        )
        total_changed = 0
        for p in products:
            if migrate_from_prev:
                new_priv, priv_changed = _rewrap_field_migrate(p.private_key_pem, prev)
                new_ws, ws_changed = _rewrap_field_migrate(p.stripe_webhook_secret, prev)
                new_ak, ak_changed = _rewrap_field_migrate(p.stripe_api_key, prev)
            else:
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
                log.info("  %s: nothing to change", p.slug)
                continue
            verb = "will re-wrap" if migrate_from_prev else "will encrypt"
            log.info("  %s: %s %s", p.slug, verb, ", ".join(changes))
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
        if migrate_from_prev:
            log.info(
                "KEK rotation complete. Remove LICENSE_KEY_ENCRYPTION_KEY_PREV "
                "from your env and redeploy."
            )
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
    parser.add_argument(
        "--migrate-from-prev", action="store_true",
        help=(
            "Decrypt every encrypted row under LICENSE_KEY_ENCRYPTION_KEY_PREV "
            "and re-encrypt under LICENSE_KEY_ENCRYPTION_KEY. Use during KEK "
            "rotation."
        ),
    )
    args = parser.parse_args()
    sys.exit(run(dry_run=args.dry_run, migrate_from_prev=args.migrate_from_prev))


if __name__ == "__main__":
    main()
