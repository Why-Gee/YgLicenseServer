"""Alembic + schema-constraint regressions.

- A clean DB run through `alembic upgrade head` produces a schema that
  SQLAlchemy can use without further DDL.
- The new schema constraints (Customer.email unique, License.status check)
  actually reject bad inputs.
- Cascade on License.installs deletes child rows when the parent is removed.
"""
from __future__ import annotations

import importlib
from datetime import UTC
from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from alembic import command

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def upgraded_db_url(tmp_path, monkeypatch) -> str:
    """Run alembic upgrade head on an empty sqlite DB and return its URL.

    The lru_cache on get_settings() makes this picky: we reload app.config
    after setting the env var so alembic.env reads the per-test DATABASE_URL.
    """
    db_path = tmp_path / "migr.db"
    url = f"sqlite:///{db_path}"
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("ADMIN_TOKEN", "x")
    monkeypatch.setenv("SESSION_SECRET", "y")
    monkeypatch.setenv("LICENSE_KEY_PEPPER", "migration_test_pepper_" + "x" * 32)

    import app.config as cfg
    importlib.reload(cfg)

    alembic_cfg = Config(str(REPO_ROOT / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    command.upgrade(alembic_cfg, "head")
    return url


def test_alembic_upgrade_head_creates_all_tables(upgraded_db_url: str) -> None:
    engine = create_engine(upgraded_db_url)
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    expected = {
        "products", "customers", "licenses", "installs", "events",
        "processed_stripe_events", "feature_presets", "alembic_version",
    }
    assert expected.issubset(tables), f"missing: {expected - tables}"


def test_webhook_deliveries_has_response_columns_after_upgrade(upgraded_db_url: str) -> None:
    """v1.4.7 migration adds response_status + response_excerpt to
    webhook_deliveries so `alembic upgrade head` (run on every prod boot)
    matches the model."""
    engine = create_engine(upgraded_db_url)
    cols = {c["name"] for c in inspect(engine).get_columns("webhook_deliveries")}
    assert {"response_status", "response_excerpt"}.issubset(cols), f"have: {sorted(cols)}"


def test_customer_email_unique_after_upgrade(upgraded_db_url: str) -> None:
    """Two customers with the same email must collide on the unique idx."""
    from sqlalchemy.exc import IntegrityError

    from app.models import Customer
    engine = create_engine(upgraded_db_url)
    from sqlalchemy.orm import Session
    with Session(engine) as s:
        s.add(Customer(email="dup@example.com"))
        s.commit()
        s.add(Customer(email="dup@example.com"))
        with pytest.raises(IntegrityError):
            s.commit()


def test_license_status_check_rejects_typo(upgraded_db_url: str) -> None:
    """`disabld` (typo) must be rejected by the CHECK constraint, not
    silently stored. A stored typo would brick /v1/check forever (it
    compares status exactly to the allowed strings)."""
    import secrets

    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import Session

    from app.models import Customer, License, Product
    from app.signing import generate_keypair
    engine = create_engine(upgraded_db_url)
    with Session(engine) as s:
        priv, pub = generate_keypair()
        p = Product(
            slug="t", name="T", key_prefix="t",
            public_key_pem=pub, private_key_pem=priv,
            jwt_issuer="t",
        )
        c = Customer(email="x@example.com")
        s.add_all([p, c])
        s.commit()
        from datetime import datetime, timedelta
        bad = License(
            product_id=p.id, customer_id=c.id,
            key=f"t_{secrets.token_urlsafe(16)}",
            plan="standard", max_users=1, features={},
            valid_until=datetime.now(UTC).replace(tzinfo=None) + timedelta(days=1),
            status="disabld",  # typo
        )
        s.add(bad)
        with pytest.raises(IntegrityError):
            s.commit()


def test_stripe_secrets_rewrap_on_upgrade(tmp_path, monkeypatch) -> None:
    """The 8a336b18bca1 migration must re-encrypt legacy plaintext stripe
    secrets when LICENSE_KEY_ENCRYPTION_KEY is set at upgrade time. Rows that
    arrived plaintext from a pre-KEK deploy should come out wrapped, leaving
    the running app able to decrypt them at request time."""
    import importlib

    from alembic.config import Config
    from cryptography.fernet import Fernet
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session

    from alembic import command

    db_path = tmp_path / "rewrap.db"
    url = f"sqlite:///{db_path}"
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("ADMIN_TOKEN", "x")
    monkeypatch.setenv("SESSION_SECRET", "y")
    monkeypatch.delenv("LICENSE_KEY_ENCRYPTION_KEY", raising=False)

    import app.config as cfg
    importlib.reload(cfg)
    import app.keystore as ks
    importlib.reload(ks)

    alembic_cfg = Config(str(REPO_ROOT / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    # Step 1: upgrade to the revision JUST BEFORE encrypt-stripe-secrets,
    # then seed a plaintext row directly.
    command.upgrade(alembic_cfg, "9a9f5b6937d8")

    from app.models import Product
    from app.signing import generate_keypair
    engine = create_engine(url)
    with Session(engine) as s:
        priv, pub = generate_keypair()
        p = Product(
            slug="legacy", name="Legacy", key_prefix="lg",
            public_key_pem=pub, private_key_pem=priv,
            jwt_issuer="lg",
            stripe_webhook_secret="whsec_LEGACY",
            stripe_api_key="sk_test_LEGACY",
        )
        s.add(p)
        s.commit()

    # Step 2: now set the KEK and run the new migration. The rewrap loop
    # should wrap the plaintext values.
    monkeypatch.setenv("LICENSE_KEY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    importlib.reload(cfg)
    importlib.reload(ks)
    command.upgrade(alembic_cfg, "head")

    # Step 3: verify the stored rows are now `enc:v1:` ciphertext.
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT stripe_webhook_secret, stripe_api_key FROM products WHERE slug = 'legacy'")
        ).first()
    assert row is not None
    assert row[0].startswith("enc:v1:")
    assert row[1].startswith("enc:v1:")

    # And the keystore decrypts them back to the original plaintext.
    from app.keystore import decrypt_secret
    assert decrypt_secret(row[0]) == "whsec_LEGACY"
    assert decrypt_secret(row[1]) == "sk_test_LEGACY"


def test_license_delete_cascades_installs(upgraded_db_url: str) -> None:
    """ORM cascade on License.installs cleans up child rows."""
    import secrets
    from datetime import datetime, timedelta

    from sqlalchemy.orm import Session

    from app.license_keys import hash_key, make_display
    from app.models import Customer, Install, License, Product
    from app.signing import generate_keypair
    engine = create_engine(upgraded_db_url)
    with Session(engine) as s:
        priv, pub = generate_keypair()
        p = Product(
            slug="t", name="T", key_prefix="t",
            public_key_pem=pub, private_key_pem=priv,
            jwt_issuer="t",
        )
        c = Customer(email="x@example.com")
        s.add_all([p, c])
        s.commit()
        key = f"t_{secrets.token_urlsafe(16)}"
        lic = License(
            product_id=p.id, customer_id=c.id,
            key=key,
            key_hash=hash_key(key),
            key_display=make_display(key),
            plan="standard", max_users=1, features={},
            valid_until=datetime.now(UTC).replace(tzinfo=None) + timedelta(days=1),
            status="active",
        )
        s.add(lic)
        s.commit()
        s.add(Install(license_id=lic.id, install_id="i1", version="1.0"))
        s.commit()
        assert s.query(Install).count() == 1
        s.delete(lic)
        s.commit()
        assert s.query(Install).count() == 0
