"""webhook_deliveries retry queue table

Revision ID: 4a247674ec5e
Revises: 8a336b18bca1
Create Date: 2026-05-18 00:00:00.000000

"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "4a247674ec5e"
down_revision: str | Sequence[str] | None = "8a336b18bca1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "license_id", sa.String(length=36),
            sa.ForeignKey("licenses.id"), nullable=True,
        ),
        sa.Column(
            "product_id", sa.String(length=36),
            sa.ForeignKey("products.id"), nullable=True,
        ),
        sa.Column("url", sa.String(length=512), nullable=False),
        sa.Column("secret", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(), nullable=True),
        sa.Column("delivered_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(length=500), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "status IN ('pending','delivered','abandoned')",
            name="ck_webhook_deliveries_status",
        ),
    )
    op.create_index(
        "ix_webhook_deliveries_license_id",
        "webhook_deliveries", ["license_id"],
    )
    op.create_index(
        "ix_webhook_deliveries_product_id",
        "webhook_deliveries", ["product_id"],
    )
    # The retry worker queries (status='pending' AND next_attempt_at <= now);
    # a composite index makes that scan a constant-time lookup at any size.
    op.create_index(
        "ix_webhook_deliveries_pending_next",
        "webhook_deliveries", ["status", "next_attempt_at"],
    )
    op.create_index(
        "ix_webhook_deliveries_created_at",
        "webhook_deliveries", ["created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_webhook_deliveries_created_at", "webhook_deliveries")
    op.drop_index("ix_webhook_deliveries_pending_next", "webhook_deliveries")
    op.drop_index("ix_webhook_deliveries_product_id", "webhook_deliveries")
    op.drop_index("ix_webhook_deliveries_license_id", "webhook_deliveries")
    op.drop_table("webhook_deliveries")
