"""encrypt stripe secrets at rest

Revision ID: 8a336b18bca1
Revises: 9a9f5b6937d8
Create Date: 2026-05-17 00:00:00.000000

Two changes:

1. Widen `products.stripe_webhook_secret` and `products.stripe_api_key` from
   `VARCHAR(128)` to `TEXT`. The KEK envelope (`enc:v1:<fernet>`) expands
   the stored value by ~100 bytes; the old 128-char cap would truncate live
   Stripe keys once wrapped.

2. Re-encrypt existing plaintext rows using `app.keystore.encrypt_secret`.
   Rows that are already wrapped (start with `enc:v1:`) are left alone -- the
   wrapper is idempotent. If `LICENSE_KEY_ENCRYPTION_KEY` is unset at upgrade
   time, encryption is a no-op and the rows stay plaintext (same posture as
   v0.8.1 for the private-key column).

Downgrade: column type goes back to `VARCHAR(128)`; rows are NOT decrypted
in-place because the old VARCHAR(128) is too short to hold the ciphertext
that legitimately fits in the new TEXT column. Run the downgrade only on a
DB where you've already manually decrypted these columns, or before any
production data has been wrapped.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "8a336b18bca1"
down_revision: str | Sequence[str] | None = "9a9f5b6937d8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # batch_alter_table because SQLite needs the table-rebuild dance for
    # column-type changes; Postgres handles it natively but the batch path
    # is a no-op there.
    with op.batch_alter_table("products") as batch:
        batch.alter_column(
            "stripe_webhook_secret",
            existing_type=sa.String(128),
            type_=sa.Text(),
            existing_nullable=True,
        )
        batch.alter_column(
            "stripe_api_key",
            existing_type=sa.String(128),
            type_=sa.Text(),
            existing_nullable=True,
        )

    # Re-encrypt existing plaintext values. Local import keeps the migration
    # importable without app code on the path (alembic envs sometimes hide it).
    from app.keystore import encrypt_secret, is_encrypted

    # Skip the data-rewrap loop when running in --sql / offline mode. Fernet
    # ciphertexts are non-deterministic, so we cannot emit a static UPDATE
    # that reproduces them. The operator can run `alembic upgrade head` online
    # in a second step (idempotent: is_encrypted() short-circuits if already
    # wrapped). Surfaces a warning at the bottom of the generated SQL.
    if op.get_context().as_sql:
        print(
            "-- NOTE: data rewrap loop skipped in --sql/offline mode. "
            "Run `alembic upgrade head` online against the same DB after "
            "applying this DDL to wrap any legacy plaintext rows."
        )
        return

    conn = op.get_bind()
    rows = conn.execute(
        sa.text("SELECT id, stripe_webhook_secret, stripe_api_key FROM products")
    ).fetchall()
    for row in rows:
        pid = row[0]
        ws = row[1]
        ak = row[2]
        new_ws = ws
        new_ak = ak
        if ws is not None and not is_encrypted(ws):
            new_ws = encrypt_secret(ws)
        if ak is not None and not is_encrypted(ak):
            new_ak = encrypt_secret(ak)
        if new_ws is not ws or new_ak is not ak:
            conn.execute(
                sa.text(
                    "UPDATE products SET stripe_webhook_secret = :ws, "
                    "stripe_api_key = :ak WHERE id = :pid"
                ),
                {"ws": new_ws, "ak": new_ak, "pid": pid},
            )


def downgrade() -> None:
    # Intentionally NOT decrypting -- VARCHAR(128) would truncate the
    # ciphertext silently. Operator is expected to decrypt before downgrade
    # if they need the narrow type back. See module docstring.
    with op.batch_alter_table("products") as batch:
        batch.alter_column(
            "stripe_api_key",
            existing_type=sa.Text(),
            type_=sa.String(128),
            existing_nullable=True,
        )
        batch.alter_column(
            "stripe_webhook_secret",
            existing_type=sa.Text(),
            type_=sa.String(128),
            existing_nullable=True,
        )
