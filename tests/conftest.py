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
        "SESSION_SECRET": "test-session",
        "COOKIE_SECURE": "false",
        "LICENSE_KEY_PEPPER": "phase4_test_pepper_" + "x" * 32,
        # Per-test backup dir; the default ./backups would pollute the repo.
        "BACKUP_DIR": str(tmp_path / "backups"),
    }
    base.update(env)
    for k, v in base.items():
        monkeypatch.setenv(k, v)
    # RESEND_API_KEY: explicit None => delete; explicit value => set.
    if env.get("RESEND_API_KEY") is None:
        monkeypatch.delenv("RESEND_API_KEY", raising=False)

    # Reload order matters: config first (env -> Settings); db next (rebuilds
    # SessionLocal off the new url); services (which import config/db) before
    # routers; routers before main. Each module captured `from X import Y`
    # symbols at first import, so we have to reload every layer to rebind.
    import app.config as cfg
    importlib.reload(cfg)
    import app.db as db
    importlib.reload(db)
    import app.email as em
    importlib.reload(em)
    import app.webhooks as wh
    importlib.reload(wh)
    import app.keystore as ks
    importlib.reload(ks)
    # license_keys captures get_settings at import; without this reload, a
    # test module that imports the app chain BEFORE the first client fixture
    # (e.g. service-level unit tests) pins a get_settings whose lru_cache was
    # populated at pytest collection time -- when no env was set -- and every
    # later hash_key() call dies with "LICENSE_KEY_PEPPER is unset".
    import app.license_keys as lk
    importlib.reload(lk)
    import app.signing as sg
    importlib.reload(sg)
    # Reset the rate-limiter's in-memory buckets between tests so one test's
    # 60 calls don't poison the next test's first call.
    import app.rate_limit as rl
    importlib.reload(rl)
    # Services first — routers import from these.
    import app.services.errors as svc_err
    importlib.reload(svc_err)
    import app.services.products as svc_p
    importlib.reload(svc_p)
    import app.services.licenses as svc_l
    importlib.reload(svc_l)
    import app.services.customers as svc_c
    importlib.reload(svc_c)
    import app.services.presets as svc_pre
    importlib.reload(svc_pre)
    import app.backup as bk
    importlib.reload(bk)
    import app.backup_s3 as bks3
    importlib.reload(bks3)
    import app.services.backups as svc_bak
    importlib.reload(svc_bak)
    import app.services.check as svc_chk
    importlib.reload(svc_chk)
    import app.services.mfa as svc_mfa
    importlib.reload(svc_mfa)
    import app.services as svc
    importlib.reload(svc)
    # Routers.
    import app.routers.api as api_mod
    importlib.reload(api_mod)
    import app.routers.exports as exports_mod
    importlib.reload(exports_mod)
    import app.stripe_webhook as sw
    importlib.reload(sw)
    import app.routers.admin_ui._deps as ui_deps
    importlib.reload(ui_deps)
    import app.routers.admin_ui.auth as ui_auth
    importlib.reload(ui_auth)
    import app.routers.admin_ui.dashboard as ui_dash
    importlib.reload(ui_dash)
    import app.routers.admin_ui.products as ui_prod
    importlib.reload(ui_prod)
    import app.routers.admin_ui.presets as ui_pre
    importlib.reload(ui_pre)
    import app.routers.admin_ui.backups as ui_bak
    importlib.reload(ui_bak)
    import app.routers.admin_ui.licenses as ui_lic
    importlib.reload(ui_lic)
    import app.routers.admin_ui.customers as ui_cust
    importlib.reload(ui_cust)
    import app.routers.admin_ui.events as ui_ev
    importlib.reload(ui_ev)
    import app.routers.admin_ui.webhook_deliveries as ui_wd
    importlib.reload(ui_wd)
    import app.routers.admin_ui.mfa as ui_mfa
    importlib.reload(ui_mfa)
    import app.routers.admin_ui as ui_mod
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
