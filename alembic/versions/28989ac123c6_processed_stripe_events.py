"""processed_stripe_events idempotency table

Revision ID: 28989ac123c6
Revises: e06b4aa2e5b1
Create Date: 2026-05-16 00:00:00.000000

"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "28989ac123c6"
down_revision: str | Sequence[str] | None = "e06b4aa2e5b1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "processed_stripe_events",
        sa.Column("id", sa.String(length=255), primary_key=True),
        sa.Column(
            "product_id", sa.String(length=36),
            sa.ForeignKey("products.id"), nullable=True,
        ),
        sa.Column("type", sa.String(length=64), nullable=False),
        sa.Column("processed_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_processed_stripe_events_product_id",
        "processed_stripe_events", ["product_id"],
    )
    op.create_index(
        "ix_processed_stripe_events_processed_at",
        "processed_stripe_events", ["processed_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_processed_stripe_events_processed_at", "processed_stripe_events")
    op.drop_index("ix_processed_stripe_events_product_id", "processed_stripe_events")
    op.drop_table("processed_stripe_events")
