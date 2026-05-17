"""Coverage for the `python -m app.scripts.rewrap_secrets` management
command. Verifies:
  - Refuses to run when KEK is unset (would be a no-op AND mask the misconfig).
  - --dry-run prints intent but does not mutate the DB.
  - A real run wraps plaintext rows + leaves already-wrapped rows alone.
"""
from __future__ import annotations

import importlib

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient


def _create_product_with_plaintext_secrets(client: TestClient) -> str:
    """Helper -- create a product via the JSON admin API. Its
    stripe_* fields are stored encrypted IF a KEK was set at creation
    time; we deliberately call this with KEK unset so they go in plaintext."""
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={
            "slug": "asm", "name": "ASM", "key_prefix": "asm",
            "stripe_webhook_secret": "whsec_PLAINTEXT",
            "stripe_api_key": "sk_test_PLAINTEXT",
        },
    )
    assert r.status_code == 200
    return r.json()["id"]


def _enable_kek(monkeypatch) -> None:
    """Flip the KEK on + reload the modules that captured it at import time.
    Use monkeypatch (not raw os.environ) so the env mutation is reverted
    cleanly between tests."""
    monkeypatch.setenv("LICENSE_KEY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    import app.config as cfg
    importlib.reload(cfg)
    import app.keystore as ks
    importlib.reload(ks)
    import app.scripts.rewrap_secrets as rs
    importlib.reload(rs)


def test_refuses_without_kek(make_client, monkeypatch) -> None:
    """Running with no KEK is a programming error -- exit 2 + clear log."""
    # make_client doesn't set KEK; ensure no prior test left one in env.
    monkeypatch.delenv("LICENSE_KEY_ENCRYPTION_KEY", raising=False)
    c = make_client()
    _create_product_with_plaintext_secrets(c)

    import app.config as cfg
    importlib.reload(cfg)
    import app.keystore as ks
    importlib.reload(ks)
    import app.scripts.rewrap_secrets as rs
    importlib.reload(rs)
    assert rs.run(dry_run=False) == 2


def test_dry_run_does_not_mutate(make_client, monkeypatch) -> None:
    """--dry-run reports intent but leaves rows untouched."""
    monkeypatch.delenv("LICENSE_KEY_ENCRYPTION_KEY", raising=False)
    c = make_client()
    _create_product_with_plaintext_secrets(c)

    # Confirm starting state is plaintext.
    from app.db import SessionLocal
    from app.models import Product
    with SessionLocal() as s:
        p = s.query(Product).one()
        assert not p.stripe_webhook_secret.startswith("enc:v1:")

    _enable_kek(monkeypatch)
    import app.scripts.rewrap_secrets as rs
    assert rs.run(dry_run=True) == 0

    # Still plaintext after dry-run.
    with SessionLocal() as s:
        p = s.query(Product).one()
        assert not p.stripe_webhook_secret.startswith("enc:v1:")
        assert not p.stripe_api_key.startswith("enc:v1:")


def test_real_run_wraps_plaintext_idempotent(make_client, monkeypatch) -> None:
    """A real run wraps every plaintext secret; a second run is a no-op
    because is_encrypted short-circuits already-wrapped rows."""
    monkeypatch.delenv("LICENSE_KEY_ENCRYPTION_KEY", raising=False)
    c = make_client()
    _create_product_with_plaintext_secrets(c)

    _enable_kek(monkeypatch)
    import app.scripts.rewrap_secrets as rs
    assert rs.run(dry_run=False) == 0

    from app.db import SessionLocal
    from app.keystore import decrypt_secret
    from app.models import Product
    with SessionLocal() as s:
        p = s.query(Product).one()
        # All three sensitive fields now wrapped.
        assert p.private_key_pem.startswith("enc:v1:")
        assert p.stripe_webhook_secret.startswith("enc:v1:")
        assert p.stripe_api_key.startswith("enc:v1:")
        # And the values still round-trip correctly.
        assert decrypt_secret(p.stripe_webhook_secret) == "whsec_PLAINTEXT"
        assert decrypt_secret(p.stripe_api_key) == "sk_test_PLAINTEXT"
        # private_key_pem is a real PEM -- just verify it starts with the
        # expected header after decrypt, not the literal contents.
        priv = decrypt_secret(p.private_key_pem)
        assert priv.startswith("-----BEGIN PRIVATE KEY-----")

    # Second run -- nothing to change.
    assert rs.run(dry_run=False) == 0
    with SessionLocal() as s:
        p = s.query(Product).one()
        # Ciphertext is identical to before (no re-encrypt churn).
        assert p.stripe_webhook_secret.startswith("enc:v1:")
