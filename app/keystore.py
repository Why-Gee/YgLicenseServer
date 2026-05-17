"""At-rest encryption of per-product Ed25519 private keys.

KEK envelope:
- A single `LICENSE_KEY_ENCRYPTION_KEY` env var (Fernet key, base64-encoded
  32 raw bytes) wraps each private_key_pem when it lands in the DB.
- Stored values are prefixed `enc:v1:` followed by the Fernet ciphertext.
  Rows without that prefix are legacy plaintext PEM; they decrypt to
  themselves and re-encrypt on next write.
- If `LICENSE_KEY_ENCRYPTION_KEY` is unset, encrypt is a no-op (stores
  plaintext). Lets dev/test work without configuring a KEK; production
  should always set one. The boot-time validator logs a CRITICAL warning
  when missing.

Why envelope: rotating the KEK only needs a re-write of each row, not a
re-keygen of every product's Ed25519 pair (which would invalidate every
client that has baked in the old public key).

Why not full library KMS: this server is single-instance and self-hosted;
adding KMS-as-a-service is out of scope. Keep the secret-management story
in the same .env that already holds ADMIN_TOKEN.
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


def encrypt_pem(pem: str) -> str:
    """Wrap a PEM-encoded private key for at-rest storage. If no KEK is set,
    returns the input unchanged so dev/test continue to work."""
    f = _fernet()
    if f is None:
        return pem
    token = f.encrypt(pem.encode("utf-8"))
    return _PREFIX + token.decode("ascii")


def decrypt_pem(stored: str) -> str:
    """Inverse of encrypt_pem. Legacy plaintext rows (no `enc:v1:` prefix)
    pass through unchanged so a deploy that turns on encryption mid-life
    keeps working until the next product is updated."""
    if not stored.startswith(_PREFIX):
        return stored
    f = _fernet()
    if f is None:
        # Encrypted in DB but no KEK at runtime -> hard error; we can't
        # sign without the private key, and a silent return would leak the
        # ciphertext as "the key" to PyJWT.
        raise RuntimeError(
            "private key is encrypted at rest but LICENSE_KEY_ENCRYPTION_KEY is unset"
        )
    payload = stored[len(_PREFIX):].encode("ascii")
    try:
        return f.decrypt(payload).decode("utf-8")
    except InvalidToken as e:
        raise RuntimeError(
            "private key decryption failed -- LICENSE_KEY_ENCRYPTION_KEY does "
            "not match the KEK that wrote this row"
        ) from e
