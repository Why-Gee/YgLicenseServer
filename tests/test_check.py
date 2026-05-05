"""End-to-end tests against in-memory SQLite + product-scoped admin endpoints."""
from __future__ import annotations

import importlib

import jwt as jwt_lib
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    db_path = tmp_path / "license.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ADMIN_TOKEN", "test-admin")
    monkeypatch.setenv("SESSION_SECRET", "test-admin")
    monkeypatch.setenv("COOKIE_SECURE", "false")

    import app.config as cfg
    import app.db as db
    importlib.reload(cfg)
    importlib.reload(db)
    import app.main as m
    importlib.reload(m)
    db.init_db()  # lifespan only runs under `with TestClient(...)`; create tables explicitly
    return TestClient(m.app)


def _create_product(client: TestClient, slug: str = "asm", prefix: str = "asm") -> dict:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": slug, "name": slug.upper(), "key_prefix": prefix},
    )
    assert r.status_code == 200, r.text
    return r.json()


def _issue(client: TestClient, slug: str = "asm", **overrides) -> str:
    body = {
        "email": "x@example.com",
        "plan": "standard",
        "valid_days": 30,
        "features": {"chat_agent": True},
    }
    body.update(overrides)
    r = client.post(
        f"/v1/admin/products/{slug}/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json=body,
    )
    assert r.status_code == 200, r.text
    return r.json()["key"]


def test_check_happy_path(client: TestClient) -> None:
    _create_product(client)
    key = _issue(client)
    assert key.startswith("asm_")
    r = client.post("/v1/check", json={"key": key, "install_id": "i1", "version": "1.0.0"})
    assert r.status_code == 200
    body = r.json()
    assert body["jwt"]
    assert body["product"] == "asm"
    assert body["features"] == {"chat_agent": True}


def test_check_jwt_signed_with_correct_product_key(client: TestClient) -> None:
    """JWT must verify against the product's published public key."""
    _create_product(client)
    pub = client.get("/v1/products/asm/pubkey").text
    key = _issue(client)
    r = client.post("/v1/check", json={"key": key, "install_id": "i1", "version": "1.0.0"})
    token = r.json()["jwt"]
    claims = jwt_lib.decode(token, pub, algorithms=["EdDSA"], options={"verify_exp": False})
    assert claims["product"] == "asm"
    assert claims["plan"] == "standard"


def test_check_invalid_key(client: TestClient) -> None:
    _create_product(client)
    r = client.post("/v1/check", json={"key": "asm_bogus", "install_id": "i1", "version": "1.0.0"})
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "invalid_key"


def test_check_revoked(client: TestClient) -> None:
    _create_product(client)
    key = _issue(client)
    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        lic = s.query(License).filter_by(key=key).one()
        lic.status = "revoked"
        s.commit()
    r = client.post("/v1/check", json={"key": key, "install_id": "i1", "version": "1.0.0"})
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "revoked"


def test_admin_requires_token(client: TestClient) -> None:
    r = client.post("/v1/admin/products", json={"slug": "x", "name": "x", "key_prefix": "x"})
    assert r.status_code == 401


def test_two_products_isolated(client: TestClient) -> None:
    """A license issued under product A must not validate under product B's pubkey."""
    _create_product(client, slug="asm", prefix="asm")
    _create_product(client, slug="other", prefix="oth")

    asm_pub = client.get("/v1/products/asm/pubkey").text
    other_pub = client.get("/v1/products/other/pubkey").text
    assert asm_pub != other_pub

    key = _issue(client, slug="asm")
    r = client.post("/v1/check", json={"key": key, "install_id": "i1", "version": "1.0.0"})
    token = r.json()["jwt"]

    # Verifies under asm pubkey
    claims = jwt_lib.decode(token, asm_pub, algorithms=["EdDSA"], options={"verify_exp": False})
    assert claims["product"] == "asm"

    # Fails under other pubkey
    with pytest.raises(jwt_lib.InvalidSignatureError):
        jwt_lib.decode(token, other_pub, algorithms=["EdDSA"], options={"verify_exp": False})


def test_duplicate_slug_rejected(client: TestClient) -> None:
    _create_product(client, slug="asm")
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "x", "key_prefix": "x"},
    )
    assert r.status_code == 409


def test_admin_ui_login_redirect(client: TestClient) -> None:
    r = client.get("/admin", follow_redirects=False)
    assert r.status_code in (303, 307)
    assert "login" in r.headers["location"]


def test_admin_ui_login_success(client: TestClient) -> None:
    r = client.post(
        "/admin/login",
        data={"token": "test-admin"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "asm_ls_session" in r.headers.get("set-cookie", "")
