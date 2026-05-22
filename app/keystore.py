"""At-rest encryption of sensitive DB-stored secrets.

KEK envelope:
- A single `LICENSE_KEY_ENCRYPTION_KEY` env var (Fernet key, base64-encoded
  32 raw bytes) wraps every secret stored at rest. Today that's:
    * `products.private_key_pem`     (Ed25519 license-signing key)
    * `products.stripe_api_key`      (Stripe live/test API key)
    * `products.stripe_webhook_secret` (Stripe endpoint signing secret)
- Stored values are prefixed `enc:v1:` followed by the Fernet ciphertext.
  Rows without that prefix are legacy plaintext; they decrypt to themselves
  and re-encrypt on the next write.
- If `LICENSE_KEY_ENCRYPTION_KEY` is unset, encrypt is a no-op (stores
  plaintext). Lets dev/test work without configuring a KEK; production
  should always set one. The boot-time validator logs a CRITICAL warning
  when missing.
- When `LICENSE_SERVER_REQUIRE_KEK=1` (v0.22+) is set in env, the no-KEK
  passthrough is upgraded to a hard `RuntimeError` so a misconfigured
  prod deploy can never silently persist plaintext. Boot also hard-exits
  in that combination — fail-fast on misconfiguration.

Why envelope: rotating the KEK only needs a re-write of each row, not a
re-keygen of every product's Ed25519 pair (which would invalidate every
client that has baked in the old public key) and not a rotation of Stripe
keys (which requires a Stripe dashboard round-trip).

Why not full library KMS: this server is single-instance and self-hosted;
adding KMS-as-a-service is out of scope. Keep the secret-management story
in the same .env that already holds ADMIN_TOKEN.

API:
- encrypt_secret / decrypt_secret  -- generic, what new code should use.
- encrypt_pem / decrypt_pem        -- back-compat aliases for the PEM call
                                      sites (signing.py, products service).
"""
from __future__ import annotations

import logging

from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings

log = logging.getLogger("license-server.keystore")

_PREFIX = "enc:v1:"


def _fernet() -> Fernet | None:
    s = get_settings()
    if not s.key_encryption_key:
        return None
    try:
        return Fernet(s.key_encryption_key.encode())
    except (ValueError, TypeError) as e:
        # Bad key format -> log and disable. Don't crash boot; an admin can
        # still log in to issue the fix without an outage.
        log.error("LICENSE_KEY_ENCRYPTION_KEY invalid (must be 32-byte url-safe base64): %s", e)
        return None


def _fernet_prev() -> Fernet | None:
    """Fernet built from LICENSE_KEY_ENCRYPTION_KEY_PREV. Internal: only the
    KEK-rotation script (`app.scripts.rewrap_secrets --migrate-from-prev`)
    should call this. Returns None when PREV is unset or malformed."""
    s = get_settings()
    if not s.key_encryption_key_prev:
        return None
    try:
        return Fernet(s.key_encryption_key_prev.encode())
    except (ValueError, TypeError) as e:
        log.error("LICENSE_KEY_ENCRYPTION_KEY_PREV invalid (must be 32-byte url-safe base64): %s", e)
        return None


def _decrypt_with(f: Fernet, stored: str) -> str:
    """Decrypt an `enc:v1:` token using an explicit Fernet (not the global
    one). Used by the KEK rotation script to decrypt with PREV before
    re-encrypting under the current KEK. Caller is responsible for checking
    `is_encrypted(stored)` first."""
    payload = stored[len(_PREFIX):].encode("ascii")
    try:
        return f.decrypt(payload).decode("utf-8")
    except InvalidToken as e:
        raise RuntimeError(
            "secret decryption failed under the supplied KEK"
        ) from e


def is_encrypted(stored: str | None) -> bool:
    """True when `stored` is already wrapped by this module. Used by data
    migrations that rewrap legacy plaintext."""
    return bool(stored) and stored.startswith(_PREFIX)


def encrypt_secret(plaintext: str | None) -> str | None:
    """Wrap a plaintext secret for at-rest storage. None passes through (so
    callers can pipe `model.field = encrypt_secret(form_value)` without
    branching on whether the value is set). If no KEK is configured, returns
    the input unchanged so dev/test continue to work."""
    if plaintext is None:
        return None
    if is_encrypted(plaintext):
        # Idempotent: caller may have already wrapped, don't double-wrap.
        return plaintext
    f = _fernet()
    if f is None:
        if get_settings().require_kek:
            raise RuntimeError(
                "KEK required (LICENSE_SERVER_REQUIRE_KEK=1) but "
                "LICENSE_KEY_ENCRYPTION_KEY is unset; refusing to write plaintext"
            )
        return plaintext
    token = f.encrypt(plaintext.encode("utf-8"))
    return _PREFIX + token.decode("ascii")


def decrypt_secret(stored: str | None) -> str | None:
    """Inverse of encrypt_secret. None passes through. Legacy plaintext rows
    (no `enc:v1:` prefix) pass through unchanged so a deploy that turns on
    encryption mid-life keeps working until the next write rewraps them."""
    if stored is None:
        return None
    if not stored.startswith(_PREFIX):
        return stored
    f = _fernet()
    if f is None:
        # Encrypted in DB but no KEK at runtime -> hard error; the caller
        # cannot use the ciphertext, and a silent return would leak it as
        # "the secret" to whatever's downstream.
        raise RuntimeError(
            "secret is encrypted at rest but LICENSE_KEY_ENCRYPTION_KEY is unset"
        )
    payload = stored[len(_PREFIX):].encode("ascii")
    try:
        return f.decrypt(payload).decode("utf-8")
    except InvalidToken as e:
        raise RuntimeError(
            "secret decryption failed -- LICENSE_KEY_ENCRYPTION_KEY does "
            "not match the KEK that wrote this row"
        ) from e


# ----- back-compat aliases ----------------------------------------------
# Older call sites (signing.py, products service) call these by their
# PEM-specific names. Keep the aliases so we don't touch every import; new
# code should use encrypt_secret / decrypt_secret directly.

def encrypt_pem(pem: str) -> str:
    """Back-compat alias for encrypt_secret on non-None PEM strings."""
    result = encrypt_secret(pem)
    assert result is not None  # input was non-None
    return result


def decrypt_pem(stored: str) -> str:
    """Back-compat alias for decrypt_secret on non-None stored strings."""
    result = decrypt_secret(stored)
    assert result is not None
    return result
