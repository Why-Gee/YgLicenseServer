"""License-server config. Per-product secrets live in the DB; this file
only carries server-wide knobs."""
from __future__ import annotations

import os
from functools import lru_cache

from pydantic import BaseModel


class Settings(BaseModel):
    database_url: str = "sqlite:///./license.db"
    admin_token: str = ""              # gates /v1/admin/* and the admin UI login
    # Signs admin UI session cookies. MUST be set independently of admin_token
    # so the two can be rotated separately; never share a single secret across
    # authn (bearer) and session signing.
    session_secret: str = ""
    jwt_ttl_days: int = 7              # JWT cache TTL clients honor
    cookie_secure: bool = True         # set false only for local http://
    resend_api_key: str = ""           # if unset, license emails are skipped (logged only)
    email_from: str = "onboarding@resend.dev"  # Resend test sender; replace once domain verified
    # Fernet key (url-safe base64 32-byte) that wraps each product's Ed25519
    # private_key_pem in the DB. Unset -> private keys stored plaintext (legacy
    # behavior). See app.keystore for the envelope format.
    key_encryption_key: str = ""
    # Previous KEK, only consulted by `python -m app.scripts.rewrap_secrets
    # --migrate-from-prev` during a KEK rotation: decrypt under PREV, re-encrypt
    # under the current KEK. Unset in steady state; the deploy script writes it
    # transiently on `-RotateSecrets` and the operator clears it after rewrap.
    key_encryption_key_prev: str = ""
    # When True (LICENSE_SERVER_REQUIRE_KEK=1 in env), the server refuses to
    # store new secrets in plaintext. encrypt_secret() raises instead of
    # passing the value through, and boot fails fast if KEK is unset.
    require_kek: bool = False
    # Postgres connection-pool tuning. Defaults match SQLAlchemy's QueuePool
    # defaults; bump pool_size when a deploy sees frequent "QueuePool limit
    # reached" warnings. pool_recycle defends against intermediate-NAT idle
    # timeouts (e.g. Cloud SQL kills connections idle > 1h) by re-opening
    # before that boundary. -1 disables recycling.
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_recycle: int = 1800  # 30 min


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(
        database_url=os.environ.get("DATABASE_URL", "sqlite:///./license.db"),
        admin_token=os.environ.get("ADMIN_TOKEN", ""),
        session_secret=os.environ.get("SESSION_SECRET", ""),
        jwt_ttl_days=int(os.environ.get("JWT_TTL_DAYS", "7")),
        cookie_secure=os.environ.get("COOKIE_SECURE", "true").lower() in ("1", "true", "yes"),
        resend_api_key=os.environ.get("RESEND_API_KEY", ""),
        email_from=os.environ.get("EMAIL_FROM", "onboarding@resend.dev"),
        key_encryption_key=os.environ.get("LICENSE_KEY_ENCRYPTION_KEY", ""),
        key_encryption_key_prev=os.environ.get("LICENSE_KEY_ENCRYPTION_KEY_PREV", ""),
        require_kek=os.environ.get("LICENSE_SERVER_REQUIRE_KEK", "").lower() in ("1", "true", "yes"),
        db_pool_size=int(os.environ.get("DB_POOL_SIZE", "5")),
        db_max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", "10")),
        db_pool_recycle=int(os.environ.get("DB_POOL_RECYCLE", "1800")),
    )
