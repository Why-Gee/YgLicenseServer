"""License-key hashing + display helpers (v1.0+).

Two columns on `licenses` cooperate:
- `key_hash`    — BLAKE2b-256 hex of the plaintext, keyed with a server
                  pepper. Used by /v1/check lookups. Without the pepper a
                  DB dump cannot brute-force keys to plaintext.
- `key_display` — Truncated form `<prefix>_<first6>…<last4>` safe to show
                  anywhere in the UI. Recognisable but non-recoverable.

The plaintext key is shown to the admin EXACTLY ONCE: the issuance HTTP
response. After that the only record on disk is the hash + display.

Why BLAKE2b: faster than SHA-256 and the natively-keyed mode means we
don't have to do HMAC-SHA256 ourselves. Hex (not base64) so the value
is index-friendly across SQLite + Postgres without encoding tricks.
"""
from __future__ import annotations

import hashlib

from app.config import get_settings


def hash_key(plaintext: str) -> str:
    """Pepper-keyed BLAKE2b-256 of `plaintext`. Returns 64 hex chars.

    Raises RuntimeError if LICENSE_KEY_PEPPER is unset — we never want to
    silently store unpeppered hashes that would mismatch the configured-
    pepper hashes once an admin sets one.
    """
    pepper = get_settings().license_key_pepper
    if not pepper:
        raise RuntimeError(
            "LICENSE_KEY_PEPPER is unset. Set a 32-byte secret in env "
            "(e.g. `python -c 'import secrets; print(secrets.token_hex(32))'`) "
            "before issuing or validating licenses."
        )
    h = hashlib.blake2b(plaintext.encode("utf-8"), digest_size=32, key=pepper.encode("utf-8"))
    return h.hexdigest()


def make_display(plaintext: str) -> str:
    """Build the safe-to-show truncated form. `<prefix>_<first6>…<last4>`
    if the key matches the `<prefix>_<body>` shape; otherwise just
    `<first6>…<last4>`. Total length capped at 32 chars."""
    if "_" in plaintext:
        prefix, _, body = plaintext.partition("_")
        head = body[:6]
        tail = body[-4:] if len(body) >= 10 else body
        return f"{prefix}_{head}…{tail}"
    head = plaintext[:6]
    tail = plaintext[-4:] if len(plaintext) >= 10 else plaintext
    return f"{head}…{tail}"
