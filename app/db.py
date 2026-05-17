from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.models import Base


def _engine():
    s = get_settings()
    is_sqlite = s.database_url.startswith("sqlite")
    connect_args = {"check_same_thread": False} if is_sqlite else {}
    # pool_pre_ping issues a SELECT 1 on each pooled connection before use,
    # so long-idle Postgres connections that the server killed don't surface
    # as InvalidCachedStatementError / OperationalError on the next /v1/check.
    # Negligible cost vs. one bad request per stale connection. Skipped for
    # sqlite which doesn't pool.
    return create_engine(
        s.database_url,
        connect_args=connect_args,
        future=True,
        pool_pre_ping=not is_sqlite,
    )


_engine_singleton = _engine()
SessionLocal = sessionmaker(bind=_engine_singleton, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    """Create tables directly via metadata. Used by tests only — prod boot
    runs `alembic upgrade head` from docker-entrypoint.sh."""
    Base.metadata.create_all(bind=_engine_singleton)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
