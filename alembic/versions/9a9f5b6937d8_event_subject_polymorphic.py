"""event subject_kind/subject_id polymorphic audit pointer

Revision ID: 9a9f5b6937d8
Revises: cb1270770a7c
Create Date: 2026-05-16 00:00:02.000000

Adds (subject_kind, subject_id) so audit rows for deleted licenses/products
remain queryable by their original natural id. license_id/product_id are
FK-enforced and get NULL'd on parent delete; this pair survives.

Backfill: existing event rows get subject_kind='license' subject_id=license_id
or subject_kind='product' subject_id=product_id where applicable.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "9a9f5b6937d8"
down_revision: str | Sequence[str] | None = "cb1270770a7c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("events") as batch:
        batch.add_column(sa.Column("subject_kind", sa.String(length=32), nullable=True))
        batch.add_column(sa.Column("subject_id", sa.String(length=64), nullable=True))
        batch.create_index("ix_events_subject_kind", ["subject_kind"])
        batch.create_index("ix_events_subject_id", ["subject_id"])

    # Backfill: license_id and product_id are still populated for existing
    # rows (the NULL'ing happens on delete, going forward).
    op.execute(
        "UPDATE events SET subject_kind='license', subject_id=license_id "
        "WHERE license_id IS NOT NULL AND subject_id IS NULL"
    )
    op.execute(
        "UPDATE events SET subject_kind='product', subject_id=product_id "
        "WHERE product_id IS NOT NULL AND subject_id IS NULL"
    )


def downgrade() -> None:
    with op.batch_alter_table("events") as batch:
        batch.drop_index("ix_events_subject_id")
        batch.drop_index("ix_events_subject_kind")
        batch.drop_column("subject_id")
        batch.drop_column("subject_kind")
