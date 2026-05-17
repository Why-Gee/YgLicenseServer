"""Shared test fixtures.

`make_client(monkeypatch, tmp_path, **env)` builds a TestClient against a
fresh sqlite DB. Centralises the importlib.reload chain that every test
file was duplicating. A proper FastAPI dependency-overrides refactor would
let us drop the reload chain entirely, but that needs reshaping every
`from app.X import Y` import site -- left as a follow-up; this fixture
unblocks the rest of the cleanup without that churn.
"""
from __future__ import annotations

import importlib
from typing import Any

import pytest
from fastapi.testclient import TestClient


def _build_client(monkeypatch, tmp_path, **env: str) -> TestClient:
    db_path = tmp_path / "license.db"
    base = {
        "DATABASE_URL": f"sqlite:///{db_path}",
        "ADMIN_TOKEN": "test-admin",
        "SESSION_SECRET": "test-admin",
        "COOKIE_SECURE": "false",
    }
    base.update(env)
    for k, v in base.items():
        monkeypatch.setenv(k, v)
    # RESEND_API_KEY: explicit None => delete; explicit value => set.
    if env.get("RESEND_API_KEY") is None:
        monkeypatch.delenv("RESEND_API_KEY", raising=False)

    # Reload order matters: config first (env -> Settings); db next (rebuilds
    # SessionLocal off the new url); domain modules last (they read config +
    # db at import time).
    import app.config as cfg
    importlib.reload(cfg)
    import app.db as db
    importlib.reload(db)
    import app.email as em
    importlib.reload(em)
    import app.webhooks as wh
    importlib.reload(wh)
    import app.api as api_mod
    importlib.reload(api_mod)
    import app.stripe_webhook as sw
    importlib.reload(sw)
    import app.admin_ui as ui_mod
    importlib.reload(ui_mod)
    import app.main as m
    importlib.reload(m)
    db.init_db()
    return TestClient(m.app)


@pytest.fixture
def make_client(monkeypatch, tmp_path):
    """Factory fixture. Use when a test needs custom env (e.g. RESEND_API_KEY).

    Example:
        def test_x(make_client):
            c = make_client(RESEND_API_KEY="re_test_key")
    """

    def _factory(**env: Any) -> TestClient:
        return _build_client(monkeypatch, tmp_path, **{k: str(v) for k, v in env.items() if v is not None})

    return _factory


@pytest.fixture
def client(monkeypatch, tmp_path) -> TestClient:
    """Default client fixture -- the common case. Tests that need
    custom env should use make_client instead."""
    return _build_client(monkeypatch, tmp_path)
