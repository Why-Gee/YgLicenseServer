"""Product edit service + router tests (v0.18.0)."""
from __future__ import annotations

import app.db as db_mod
from app.models import Event, Product
from app.services import products as products_svc
from fastapi.testclient import TestClient
import pytest


# ------------------------- service-level tests ----------------------------

def _seed_product(slug: str = "myapp", name: str = "My App", key_prefix: str = "myapp"):
    with db_mod.SessionLocal() as db:
        return products_svc.create_product(
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


def test_update_product_changes_jwt_issuer(client: TestClient) -> None:
    _seed_product()
    with db_mod.SessionLocal() as db:
        products_svc.update_product(db, "myapp", jwt_issuer="custom-iss")
        p = db.query(Product).filter_by(slug="myapp").one()
        assert p.jwt_issuer == "custom-iss"


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
