"""allow_http_webhook column

Revision ID: 82b53e74e9ac
Revises: 570f101254e2
Create Date: 2026-05-22 16:44:58.722834

Adds licenses.allow_http_webhook (bool, default False). Backfills True
for any existing row whose webhook_url starts with http:// so a deploy
that already had http webhooks configured keeps working post-upgrade.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = '82b53e74e9ac'
down_revision: str | Sequence[str] | None = '570f101254e2'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("licenses") as batch:
        batch.add_column(
            sa.Column(
                "allow_http_webhook",
                sa.Integer,
                nullable=False,
                server_default=sa.text("0"),
            )
        )
    # Backfill: existing http:// URLs were configured deliberately; preserve.
    op.execute(
        "UPDATE licenses SET allow_http_webhook = 1 "
        "WHERE webhook_url LIKE 'http://%'"
    )


def downgrade() -> None:
    with op.batch_alter_table("licenses") as batch:
        batch.drop_column("allow_http_webhook")
