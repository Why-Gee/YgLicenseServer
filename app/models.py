"""SQLAlchemy ORM (sync). Multi-product license server.

Each `Product` is a separately-licensed app. Products own their own Ed25519
keypair (stored in the DB; back up the DB to back up everything that matters)
and optionally their own Stripe/Paddle webhook secret.

Licenses, customers, installs, events are scoped per-product via foreign
key — no cross-product leakage even with one shared DB.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy import event as sa_event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Allowed license status values. Kept in sync with the CheckConstraint on
# License.status and with the status:* event-type strings emitted in
# admin_ui.py and stripe_webhook.py.
LICENSE_STATUSES = ("active", "delinquent", "disabled", "revoked")


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow_naive() -> datetime:
    """Tz-naive UTC default for DateTime columns. SQLAlchemy stores these as
    naive in SQLite and as TIMESTAMP WITHOUT TIME ZONE in Postgres; using
    datetime.now(UTC).replace(tzinfo=None) silences the utcnow() deprecation
    warning without changing the wire format."""
    return datetime.now(UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Product(Base):
    __tablename__ = "products"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Keypair: bake `public_key_pem` into the client image; `private_key_pem`
    # never leaves this server. Both stored as ASCII-armored PEM.
    public_key_pem: Mapped[str] = mapped_column(Text)
    private_key_pem: Mapped[str] = mapped_column(Text)

    # License keys for this product start with this prefix. Lets /v1/check
    # short-circuit lookup and helps humans recognize keys at a glance.
    key_prefix: Mapped[str] = mapped_column(String(16))

    # Optional per-product Stripe/Paddle webhook secret. The webhook endpoint
    # is product-scoped: /v1/products/<slug>/stripe-webhook.
    # Stored encrypted under the same KEK as `private_key_pem` (see
    # app.keystore). Column type is Text so the ciphertext (Fernet token,
    # ~100B beyond the plaintext) fits. Access through app.keystore.decrypt_secret.
    stripe_webhook_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    stripe_api_key: Mapped[str | None] = mapped_column(Text, nullable=True)

    # JWT issuer claim for tokens minted on behalf of this product.
    jwt_issuer: Mapped[str] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)

    licenses: Mapped[list[License]] = relationship(
        back_populates="product",
        # No cascade-delete on the relationship: products are deleted by the
        # _delete_product helper which walks each license through
        # _delete_license (fires webhook, snapshots audit row). Cascade here
        # would skip that path.
    )


class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    stripe_customer_id: Mapped[str | None] = mapped_column(
        String(64), unique=True, nullable=True, index=True
    )
    # Unique to prevent races where two concurrent admin_issue / Stripe paid
    # events both see "no customer" and create two rows for the same address.
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    # Optional display name. Populated from the issue/edit form; falls back
    # to email in the UI when blank.
    name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)

    licenses: Mapped[list[License]] = relationship(back_populates="customer")


class License(Base):
    __tablename__ = "licenses"
    __table_args__ = (
        # Enforce the documented status vocabulary at the DB layer so a typo
        # in code (`disabld`) doesn't silently brick a row -- /v1/check
        # compares status exactly and an off-by-one value would 200 forever.
        CheckConstraint(
            f"status IN {LICENSE_STATUSES!r}",
            name="ck_licenses_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id"), index=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id"), index=True)
    key: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    plan: Mapped[str] = mapped_column(String(32))
    max_users: Mapped[int] = mapped_column(Integer, default=10)
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    valid_until: Mapped[datetime] = mapped_column(DateTime)
    # Allowed values: see LICENSE_STATUSES. disabled = soft toggle (admin can
    # re-enable). revoked = intended permanent. Enforced by ck_licenses_status.
    status: Mapped[str] = mapped_column(String(16), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)

    # Optional outbound webhook. When set, LS POSTs status-change / delete
    # events to webhook_url, signed with webhook_secret (HMAC-SHA256). Lets
    # the customer react to admin actions instantly instead of polling.
    webhook_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    webhook_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)

    product: Mapped[Product] = relationship(back_populates="licenses")
    customer: Mapped[Customer] = relationship(back_populates="licenses")
    # When a License is deleted, fan out and delete its Installs in the same
    # session flush. Events get their license_id NULL'd in the delete helper
    # so the audit trail survives, but installs are operationally pointless
    # once the parent license is gone.
    installs: Mapped[list[Install]] = relationship(
        back_populates="license", cascade="all, delete-orphan"
    )


class Install(Base):
    __tablename__ = "installs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    license_id: Mapped[str] = mapped_column(ForeignKey("licenses.id"), index=True)
    install_id: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[str] = mapped_column(String(32))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)
    ip_addr_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    license: Mapped[License] = relationship(back_populates="installs")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    license_id: Mapped[str | None] = mapped_column(
        ForeignKey("licenses.id"), nullable=True, index=True
    )
    product_id: Mapped[str | None] = mapped_column(
        ForeignKey("products.id"), nullable=True, index=True
    )
    # Polymorphic audit pointer. license_id/product_id are FK-enforced and
    # get NULL'd when the parent row is deleted; subject_kind+subject_id
    # store the natural identity at event-emission time so a "what happened
    # to license X" query still resolves after X is gone. Indexed on
    # (subject_kind, subject_id) so the join works without a fan-out scan.
    subject_kind: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    subject_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    type: Mapped[str] = mapped_column(String(64), index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive, index=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)


@sa_event.listens_for(Event, "before_insert")
def _event_autofill_subject(_mapper, _conn, target: Event) -> None:
    """Auto-populate subject_kind+subject_id from whichever FK is set, so
    call sites don't have to thread it through. Licenses take precedence
    when both are set (the event is about the license; product is context)."""
    if target.subject_id:
        return
    if target.license_id:
        target.subject_kind = "license"
        target.subject_id = target.license_id
    elif target.product_id:
        target.subject_kind = "product"
        target.subject_id = target.product_id
    elif target.payload:
        # Deletion audits write license_id=None but stash the dead id in
        # payload (e.g. payload['license_id']). Pick it up so the trail
        # remains queryable.
        pid = target.payload.get("license_id") if isinstance(target.payload, dict) else None
        if pid:
            target.subject_kind = "license"
            target.subject_id = str(pid)
            return
        pid = target.payload.get("product_id") if isinstance(target.payload, dict) else None
        if pid:
            target.subject_kind = "product"
            target.subject_id = str(pid)


class ProcessedStripeEvent(Base):
    """Idempotency table for Stripe webhook delivery. Stripe occasionally
    redelivers the same event.id (network blip, manual retry); without this
    table an invoice.paid redelivery would extend valid_until twice.

    Inserted inside the stripe_webhook handler before any side effect; if the
    insert collides on the PK we skip the event."""

    __tablename__ = "processed_stripe_events"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)  # stripe event id
    product_id: Mapped[str | None] = mapped_column(
        ForeignKey("products.id"), nullable=True, index=True
    )
    type: Mapped[str] = mapped_column(String(64))
    processed_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive, index=True)
