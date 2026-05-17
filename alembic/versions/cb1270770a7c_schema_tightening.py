"""schema tightening: customers.email unique, licenses.status check

Revision ID: cb1270770a7c
Revises: 28989ac123c6
Create Date: 2026-05-16 00:00:01.000000

Adds:
- UNIQUE(customers.email) — prevents duplicate-customer race on dedupe
- CHECK(licenses.status IN ('active','delinquent','disabled','revoked'))

The cascade on installs is handled in code via the relationship cascade and
does not need a schema change (no ON DELETE clause is added; the ORM still
manages the delete fan-out).
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "cb1270770a7c"
down_revision: str | Sequence[str] | None = "28989ac123c6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_STATUSES = ("active", "delinquent", "disabled", "revoked")


def upgrade() -> None:
    # customers.email -> unique. Drop the prior plain index first; the
    # unique constraint creates its own index.
    with op.batch_alter_table("customers") as batch:
        batch.drop_index("ix_customers_email")
        batch.create_unique_constraint("uq_customers_email", ["email"])
        batch.create_index("ix_customers_email", ["email"])

    # licenses.status -> check constraint.
    with op.batch_alter_table("licenses") as batch:
        batch.create_check_constraint(
            "ck_licenses_status",
            "status IN ({})".format(", ".join(repr(s) for s in _STATUSES)),
        )


def downgrade() -> None:
    with op.batch_alter_table("licenses") as batch:
        batch.drop_constraint("ck_licenses_status", type_="check")
    with op.batch_alter_table("customers") as batch:
        batch.drop_index("ix_customers_email")
        batch.drop_constraint("uq_customers_email", type_="unique")
        batch.create_index("ix_customers_email", ["email"])
