"""Product edit tests (v0.18.0)."""
from __future__ import annotations

import app.db as db_mod
from app.models import Event, Product
from app.services import products as products_svc
from fastapi.testclient import TestClient
import pytest


# ------------------------- service-level tests ----------------------------

def _seed_product(slug: str = "myapp", name: str = "My App", key_prefix: str = "myapp"):
    with db_mod.SessionLocal() as db:
        products_svc.create_product(
            db, slug=slug, name=name, key_prefix=key_prefix,
        )


def test_update_product_changes_name_and_description(client: TestClient) -> None:
    _seed_product()
    with db_mod.SessionLocal() as db:
        products_svc.update_product(
            db, "myapp", name="New Name", description="hello",
        )
        p = db.query(Product).filter_by(slug="myapp").one()
        assert p.name == "New Name"
        assert p.description == "hello"
        ev = db.query(Event).filter_by(type="product:edited").one()
        assert ev.payload["slug"] == "myapp"
        assert ev.payload["changes"] == {
            "name": ["My App", "New Name"],
            "description": [None, "hello"],
        }


def test_update_product_renames_slug(client: TestClient) -> None:
    _seed_product()
    with db_mod.SessionLocal() as db:
        products_svc.update_product(db, "myapp", new_slug="renamed")
        assert db.query(Product).filter_by(slug="renamed").one_or_none() is not None
        assert db.query(Product).filter_by(slug="myapp").one_or_none() is None


def test_update_product_changes_key_prefix(client: TestClient) -> None:
    _seed_product()
    with db_mod.SessionLocal() as db:
        products_svc.update_product(db, "myapp", key_prefix="newpfx")
        p = db.query(Product).filter_by(slug="myapp").one()
        assert p.key_prefix == "newpfx"


def test_update_product_key_prefix_flows_to_new_licenses(client: TestClient) -> None:
    from app.models import Product
    from app.services.licenses import issue_license

    _seed_product(slug="myapp", key_prefix="myapp")

    # Issue a license under the old prefix.
    with db_mod.SessionLocal() as db:
        product = db.query(Product).filter_by(slug="myapp").one()
        old_result = issue_license(db, product=product, email="old@example.com")
        old_key = old_result.license.key

    # Change the key_prefix.
    with db_mod.SessionLocal() as db:
        products_svc.update_product(db, "myapp", key_prefix="newpfx")

    # Issue a second license under the new prefix.
    with db_mod.SessionLocal() as db:
        product = db.query(Product).filter_by(slug="myapp").one()
        new_result = issue_license(db, product=product, email="new@example.com")
        new_key = new_result.license.key

    assert old_key.startswith("myapp_"), f"old key should keep original prefix, got {old_key!r}"
    assert new_key.startswith("newpfx_"), f"new key should use updated prefix, got {new_key!r}"


def test_update_product_changes_jwt_issuer(client: TestClient) -> None:
    _seed_product()
    with db_mod.SessionLocal() as db:
        products_svc.update_product(db, "myapp", jwt_issuer="custom-iss")
        p = db.query(Product).filter_by(slug="myapp").one()
        assert p.jwt_issuer == "custom-iss"


def test_update_product_jwt_issuer_flows_to_new_licenses(client: TestClient) -> None:
    import jwt as jwt_lib

    _seed_product(slug="myapp", key_prefix="myapp")

    # Change jwt_issuer.
    with db_mod.SessionLocal() as db:
        products_svc.update_product(db, "myapp", jwt_issuer="new-iss")

    # Issue a license via the HTTP API.
    r = client.post(
        "/v1/admin/products/myapp/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={"email": "jwttest@example.com", "plan": "standard", "valid_days": 30},
    )
    assert r.status_code == 200, r.text
    issued_key = r.json()["key"]

    # Hit /v1/check to get a minted JWT.
    r = client.post(
        "/v1/check",
        json={"key": issued_key, "install_id": "inst-1", "version": "1.0.0"},
    )
    assert r.status_code == 200, r.text
    token = r.json()["jwt"]

    # Decode without verifying signature — checking claims only.
    claims = jwt_lib.decode(
        token, algorithms=["EdDSA"], options={"verify_signature": False, "verify_exp": False},
    )
    assert claims["iss"] == "new-iss"


def test_update_product_rejects_slug_collision(client: TestClient) -> None:
    from app.services.errors import Conflict
    _seed_product(slug="a", name="A", key_prefix="a")
    _seed_product(slug="b", name="B", key_prefix="b")
    with db_mod.SessionLocal() as db, pytest.raises(Conflict):
        products_svc.update_product(db, "a", new_slug="b")


def test_update_product_rejects_invalid_slug(client: TestClient) -> None:
    from app.services.errors import ValidationFailed
    _seed_product()
    with db_mod.SessionLocal() as db, pytest.raises(ValidationFailed):
        products_svc.update_product(db, "myapp", new_slug="Bad Slug!")


def test_update_product_rejects_invalid_key_prefix(client: TestClient) -> None:
    from app.services.errors import ValidationFailed
    _seed_product()
    with db_mod.SessionLocal() as db, pytest.raises(ValidationFailed):
        products_svc.update_product(db, "myapp", key_prefix="BAD-PFX")


def test_update_product_missing_slug_raises(client: TestClient) -> None:
    from app.services.errors import NotFound
    with db_mod.SessionLocal() as db, pytest.raises(NotFound):
        products_svc.update_product(db, "nope", name="x")


def test_update_product_noop_writes_no_event(client: TestClient) -> None:
    _seed_product()
    with db_mod.SessionLocal() as db:
        n_before = db.query(Event).filter_by(type="product:edited").count()
        products_svc.update_product(db, "myapp")  # nothing to change
        n_after = db.query(Event).filter_by(type="product:edited").count()
        assert n_before == n_after
