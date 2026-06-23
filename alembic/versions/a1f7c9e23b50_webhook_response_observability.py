"""webhook delivery response observability

Revision ID: a1f7c9e23b50
Revises: 3f8b2c91d4ae
Create Date: 2026-06-22 21:00:00.000000

Adds webhook_deliveries.response_status (HTTP code the receiver returned on
the last attempt; NULL = never reached the receiver) and response_excerpt
(receiver body, success or failure). Additive + nullable: existing rows read
NULL (rendered as an em-dash). No backfill — historical rows stay NULL.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = 'a1f7c9e23b50'
down_revision: str | Sequence[str] | None = '3f8b2c91d4ae'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("webhook_deliveries") as batch:
        batch.add_column(sa.Column("response_status", sa.Integer, nullable=True))
        batch.add_column(sa.Column("response_excerpt", sa.String(500), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("webhook_deliveries") as batch:
        batch.drop_column("response_excerpt")
        batch.drop_column("response_status")
