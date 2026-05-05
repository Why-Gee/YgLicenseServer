from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.models import Base


def _engine():
    s = get_settings()
    connect_args = {"check_same_thread": False} if s.database_url.startswith("sqlite") else {}
    return create_engine(s.database_url, connect_args=connect_args, future=True)


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
