"""KEK envelope (L4) regressions.

- encrypt_pem(x) is a no-op when no KEK is set (dev/test compat).
- With a KEK, encrypt_pem(x) prefixes `enc:v1:` and decrypt_pem reverses it.
- Legacy plaintext rows still decrypt (decrypt_pem returns input unchanged
  when no prefix is present), so a deploy that turns on encryption mid-life
  keeps working until a row is rewritten.
- Wrong KEK -> RuntimeError on decrypt; production must fail loud, not sign
  with ciphertext as a string.
"""
from __future__ import annotations

import importlib

import pytest
from cryptography.fernet import Fernet


def _reload_config():
    import app.config as cfg
    importlib.reload(cfg)
    import app.keystore as ks
    importlib.reload(ks)


def test_encrypt_noop_when_kek_unset(monkeypatch) -> None:
    monkeypatch.delenv("LICENSE_KEY_ENCRYPTION_KEY", raising=False)
    _reload_config()
    from app.keystore import decrypt_pem, encrypt_pem
    pem = "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----"
    assert encrypt_pem(pem) == pem
    assert decrypt_pem(pem) == pem


def test_encrypt_decrypt_roundtrip(monkeypatch) -> None:
    monkeypatch.setenv("LICENSE_KEY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    _reload_config()
    from app.keystore import decrypt_pem, encrypt_pem
    pem = "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----"
    wrapped = encrypt_pem(pem)
    assert wrapped.startswith("enc:v1:")
    assert wrapped != pem
    assert decrypt_pem(wrapped) == pem


def test_decrypt_legacy_plaintext_passes_through(monkeypatch) -> None:
    """Pre-encryption rows in the DB don't have the `enc:v1:` prefix; they
    should be returned unchanged so a deploy that adopts encryption mid-life
    doesn't break old products."""
    monkeypatch.setenv("LICENSE_KEY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    _reload_config()
    from app.keystore import decrypt_pem
    pem = "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----"
    assert decrypt_pem(pem) == pem


def test_decrypt_with_wrong_kek_raises(monkeypatch) -> None:
    """A KEK rotation that lost the old key must not silently return bytes
    that look like a key -- otherwise PyJWT would happily sign with garbage."""
    monkeypatch.setenv("LICENSE_KEY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    _reload_config()
    from app.keystore import encrypt_pem
    wrapped = encrypt_pem("plaintext")

    monkeypatch.setenv("LICENSE_KEY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    _reload_config()
    from app.keystore import decrypt_pem
    with pytest.raises(RuntimeError, match="decryption failed"):
        decrypt_pem(wrapped)


def test_decrypt_encrypted_value_without_kek_raises(monkeypatch) -> None:
    """Encrypted row in DB but the runtime has no KEK -> hard error rather
    than handing PyJWT the ciphertext blob to sign with."""
    monkeypatch.setenv("LICENSE_KEY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    _reload_config()
    from app.keystore import encrypt_pem
    wrapped = encrypt_pem("plaintext")

    monkeypatch.delenv("LICENSE_KEY_ENCRYPTION_KEY", raising=False)
    _reload_config()
    from app.keystore import decrypt_pem
    with pytest.raises(RuntimeError, match="LICENSE_KEY_ENCRYPTION_KEY is unset"):
        decrypt_pem(wrapped)


def test_encrypt_secret_handles_none(monkeypatch) -> None:
    """`encrypt_secret(None)` must pass through so callers can pipe optional
    fields without branching, e.g. `model.field = encrypt_secret(form_value)`
    when form_value is allowed to be None."""
    monkeypatch.setenv("LICENSE_KEY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    _reload_config()
    from app.keystore import decrypt_secret, encrypt_secret
    assert encrypt_secret(None) is None
    assert decrypt_secret(None) is None


def test_encrypt_secret_idempotent(monkeypatch) -> None:
    """Double-wrap protection: passing an already-encrypted value back into
    encrypt_secret returns it unchanged. Matters for the migration path
    where the row may have been rewrapped by an earlier upgrade run."""
    monkeypatch.setenv("LICENSE_KEY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    _reload_config()
    from app.keystore import encrypt_secret, is_encrypted
    wrapped = encrypt_secret("plaintext")
    assert is_encrypted(wrapped)
    twice = encrypt_secret(wrapped)
    assert twice == wrapped
