"""admin_mfa table

Revision ID: 570f101254e2
Revises: 5c836611873a
Create Date: 2026-05-22 15:59:23.813777

Single-row table for admin MFA enrolment state. Default is empty (no row).
TOTP secret is stored Fernet-encrypted; recovery codes are stored as SHA-256
hex digests in a JSON list.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = '570f101254e2'
down_revision: str | Sequence[str] | None = '5c836611873a'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "admin_mfa",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("enabled", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("secret_encrypted", sa.Text, nullable=True),
        sa.Column("recovery_codes_hashed", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column("last_used_at", sa.DateTime, nullable=True),
        sa.CheckConstraint("id = 1", name="ck_admin_mfa_single_row"),
    )


def downgrade() -> None:
    op.drop_table("admin_mfa")
