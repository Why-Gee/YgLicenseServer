"""SQLAlchemy ORM (sync). Multi-product license server.

Each `Product` is a separately-licensed app. Products own their own Ed25519
keypair (stored in the DB; back up the DB to back up everything that matters)
and optionally their own Stripe/Paddle webhook secret.

Licenses, customers, installs, events are scoped per-product via foreign
key — no cross-product leakage even with one shared DB.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return str(uuid.uuid4())


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
    stripe_webhook_secret: Mapped[str | None] = mapped_column(String(128), nullable=True)
    stripe_api_key: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # JWT issuer claim for tokens minted on behalf of this product.
    jwt_issuer: Mapped[str] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    licenses: Mapped[list[License]] = relationship(back_populates="product")


class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    stripe_customer_id: Mapped[str | None] = mapped_column(
        String(64), unique=True, nullable=True, index=True
    )
    email: Mapped[str] = mapped_column(String(320), index=True)
    # Optional display name. Populated from the issue/edit form; falls back
    # to email in the UI when blank.
    name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    licenses: Mapped[list[License]] = relationship(back_populates="customer")


class License(Base):
    __tablename__ = "licenses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id"), index=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id"), index=True)
    key: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    plan: Mapped[str] = mapped_column(String(32))
    max_users: Mapped[int] = mapped_column(Integer, default=10)
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    valid_until: Mapped[datetime] = mapped_column(DateTime)
    # Allowed values: active | delinquent | disabled | revoked.
    # disabled = soft toggle (admin can re-enable). revoked = intended permanent.
    status: Mapped[str] = mapped_column(String(16), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Optional outbound webhook. When set, LS POSTs status-change / delete
    # events to webhook_url, signed with webhook_secret (HMAC-SHA256). Lets
    # the customer react to admin actions instantly instead of polling.
    webhook_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    webhook_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)

    product: Mapped[Product] = relationship(back_populates="licenses")
    customer: Mapped[Customer] = relationship(back_populates="licenses")
    installs: Mapped[list[Install]] = relationship(back_populates="license")


class Install(Base):
    __tablename__ = "installs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    license_id: Mapped[str] = mapped_column(ForeignKey("licenses.id"), index=True)
    install_id: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[str] = mapped_column(String(32))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
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
    type: Mapped[str] = mapped_column(String(64), index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
