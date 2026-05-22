"""webhook url source

Revision ID: 5c836611873a
Revises: 4a247674ec5e
Create Date: 2026-05-22 14:29:37.343735

Locks down admin-configured webhook URLs against /v1/check overrides.

Adds licenses.webhook_url_source with two values:
  - 'admin': URL was set via admin UI / admin JSON API. /v1/check refuses
    public_url updates against these rows.
  - 'self':  URL was set (or will be set) via /v1/check's public_url. /v1/check
    may update the URL freely.

Backfill: every existing row with a non-NULL webhook_url is set to 'admin'
(locked); rows with NULL webhook_url stay at the 'self' default. Admin can
flip via UI on a per-license basis if they want client self-registration.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "5c836611873a"
down_revision: str | Sequence[str] | None = "4a247674ec5e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("licenses") as batch:
        batch.add_column(
            sa.Column(
                "webhook_url_source",
                sa.String(16),
                nullable=False,
                server_default=sa.text("'self'"),
            )
        )
        batch.create_check_constraint(
            "ck_licenses_webhook_url_source",
            "webhook_url_source IN ('admin','self')",
        )
    # Backfill: existing rows with a URL are admin-managed.
    op.execute(
        "UPDATE licenses SET webhook_url_source = 'admin' "
        "WHERE webhook_url IS NOT NULL"
    )


def downgrade() -> None:
    with op.batch_alter_table("licenses") as batch:
        batch.drop_constraint("ck_licenses_webhook_url_source", type_="check")
        batch.drop_column("webhook_url_source")
