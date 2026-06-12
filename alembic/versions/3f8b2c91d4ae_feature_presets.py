"""feature presets table

Revision ID: 3f8b2c91d4ae
Revises: 1413d5d1702b
Create Date: 2026-06-12

Admin-defined authoring templates for license `features` keys. Pure UI
affordance (typo-free key insertion with a default value) — LS attaches no
semantics to any key. product_id NULL = global preset.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '3f8b2c91d4ae'
down_revision: str | Sequence[str] | None = '1413d5d1702b'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "feature_presets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "product_id", sa.String(36),
            sa.ForeignKey("products.id"), nullable=True,
        ),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("value_type", sa.String(16), nullable=False),
        sa.Column("default_value", sa.JSON, nullable=True),
        sa.Column(
            "created_at", sa.DateTime, nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.CheckConstraint(
            "value_type IN ('bool','number','string','json')",
            name="ck_feature_presets_value_type",
        ),
        sa.UniqueConstraint("product_id", "key", name="uq_feature_presets_product_key"),
    )
    op.create_index("ix_feature_presets_product_id", "feature_presets", ["product_id"])
    # Global presets (product_id IS NULL) need a partial unique index — a
    # plain UNIQUE treats NULLs as distinct on both SQLite and Postgres, so
    # the composite constraint above wouldn't stop duplicate global keys.
    op.create_index(
        "uq_feature_presets_global_key", "feature_presets", ["key"],
        unique=True,
        sqlite_where=sa.text("product_id IS NULL"),
        postgresql_where=sa.text("product_id IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_feature_presets_global_key", table_name="feature_presets")
    op.drop_index("ix_feature_presets_product_id", table_name="feature_presets")
    op.drop_table("feature_presets")
