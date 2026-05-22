"""license key hash columns

Revision ID: 1413d5d1702b
Revises: 82b53e74e9ac
Create Date: 2026-05-22 00:00:00.000000

v1.0 breaking change. Adds licenses.key_hash + key_display columns.
Both nullable at first; populated by the data backfill loop below
using the configured LICENSE_KEY_PEPPER; then constraints applied.

Requires LICENSE_KEY_PEPPER in the env at upgrade time when rows are
present. If unset and the table has rows, the migration aborts so the
operator can't silently set the pepper to a different value later
(which would make every backfilled hash mismatch the live lookups).
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "1413d5d1702b"
down_revision: str | Sequence[str] | None = "82b53e74e9ac"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Skip the data-backfill loop in --sql / offline mode for the same reason
    # the 8a336b18bca1 migration does: non-deterministic ops can't be emitted
    # as static SQL.
    if op.get_context().as_sql:
        print(
            "-- NOTE: license-key hash backfill skipped in --sql/offline mode. "
            "Run `alembic upgrade head` online against the same DB after "
            "applying this DDL with LICENSE_KEY_PEPPER set."
        )
        with op.batch_alter_table("licenses") as batch:
            batch.add_column(sa.Column("key_hash", sa.String(64), nullable=True))
            batch.add_column(sa.Column("key_display", sa.String(32), nullable=True))
        return

    # Phase 1: add columns nullable so the backfill can populate them first.
    with op.batch_alter_table("licenses") as batch:
        batch.add_column(sa.Column("key_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("key_display", sa.String(32), nullable=True))

    # Phase 2: pepper check + backfill.
    from app.config import get_settings
    from app.license_keys import hash_key, make_display

    s = get_settings()
    conn = op.get_bind()
    rows = conn.execute(
        sa.text("SELECT id, key FROM licenses WHERE key_hash IS NULL")
    ).fetchall()

    if rows and not s.license_key_pepper:
        raise RuntimeError(
            "license-key hash migration: rows present but LICENSE_KEY_PEPPER "
            "is unset. Set the pepper before running this migration; the "
            "value MUST then be stable for the lifetime of the deployment."
        )

    for row in rows:
        plaintext = row[1]
        conn.execute(
            sa.text(
                "UPDATE licenses SET key_hash = :h, key_display = :d "
                "WHERE id = :pid"
            ),
            {"h": hash_key(plaintext), "d": make_display(plaintext), "pid": row[0]},
        )

    # Phase 3: tighten to NOT NULL + UNIQUE on key_hash.
    with op.batch_alter_table("licenses") as batch:
        batch.alter_column("key_hash", existing_type=sa.String(64), nullable=False)
        batch.alter_column("key_display", existing_type=sa.String(32), nullable=False)
        batch.create_unique_constraint("uq_licenses_key_hash", ["key_hash"])
        batch.create_index("ix_licenses_key_hash", ["key_hash"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("licenses") as batch:
        batch.drop_index("ix_licenses_key_hash")
        batch.drop_constraint("uq_licenses_key_hash", type_="unique")
        batch.drop_column("key_display")
        batch.drop_column("key_hash")
