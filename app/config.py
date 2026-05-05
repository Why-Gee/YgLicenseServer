"""License-server config. Per-product secrets live in the DB; this file
only carries server-wide knobs."""
from __future__ import annotations

import os
from functools import lru_cache

from pydantic import BaseModel


class Settings(BaseModel):
    database_url: str = "sqlite:///./license.db"
    admin_token: str = ""              # gates /v1/admin/* and the admin UI login
    session_secret: str = ""           # signs admin UI session cookies
    jwt_ttl_days: int = 7              # JWT cache TTL clients honor
    cookie_secure: bool = True         # set false only for local http://


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(
        database_url=os.environ.get("DATABASE_URL", "sqlite:///./license.db"),
        admin_token=os.environ.get("ADMIN_TOKEN", ""),
        session_secret=os.environ.get("SESSION_SECRET", os.environ.get("ADMIN_TOKEN", "")),
        jwt_ttl_days=int(os.environ.get("JWT_TTL_DAYS", "7")),
        cookie_secure=os.environ.get("COOKIE_SECURE", "true").lower() in ("1", "true", "yes"),
    )
