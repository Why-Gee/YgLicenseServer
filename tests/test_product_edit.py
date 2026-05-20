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


# ------------------------- router-level tests -----------------------------

def _login(client: TestClient) -> dict[str, str]:
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return {"ls_session": r.cookies["ls_session"]}


def _csrf(cookies: dict[str, str]) -> str:
    from app.config import get_settings
    from app.security import csrf_token
    return csrf_token(get_settings().session_secret, cookies["ls_session"])


def _admin_create(client: TestClient, slug: str = "myapp") -> None:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": slug, "name": slug.upper(), "key_prefix": slug},
    )
    assert r.status_code == 200, r.text


def test_edit_route_requires_csrf(client: TestClient) -> None:
    _admin_create(client)
    cookies = _login(client)
    r = client.post(
        "/admin/products/myapp/edit",
        data={"name": "x"},
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 403


def test_edit_route_requires_login(client: TestClient) -> None:
    _admin_create(client)
    r = client.post(
        "/admin/products/myapp/edit",
        data={"name": "x", "csrf_token": "irrelevant"},
        follow_redirects=False,
    )
    # LoginRequired handler emits a 303 to /admin/login.
    assert r.status_code == 303
    assert r.headers["location"].startswith("/admin/login")


def test_edit_route_missing_product_404(client: TestClient) -> None:
    cookies = _login(client)
    r = client.post(
        "/admin/products/nope/edit",
        data={"name": "x", "csrf_token": _csrf(cookies)},
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 404


def test_edit_route_success_redirects_with_product_edited(client: TestClient) -> None:
    _admin_create(client)
    cookies = _login(client)
    r = client.post(
        "/admin/products/myapp/edit",
        data={
            "slug": "myapp", "name": "Renamed",
            "key_prefix": "myapp", "jwt_issuer": "",
            "description": "",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/admin/products?product_edited=myapp"


def test_edit_route_renames_slug_in_redirect(client: TestClient) -> None:
    _admin_create(client, slug="orig")
    cookies = _login(client)
    r = client.post(
        "/admin/products/orig/edit",
        data={
            "slug": "renamed", "name": "ORIG",
            "key_prefix": "orig", "jwt_issuer": "",
            "description": "",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/admin/products?product_edited=renamed"


def test_edit_route_slug_collision_redirects_with_error(client: TestClient) -> None:
    _admin_create(client, slug="a")
    _admin_create(client, slug="b")
    cookies = _login(client)
    r = client.post(
        "/admin/products/a/edit",
        data={
            "slug": "b", "name": "A",
            "key_prefix": "a", "jwt_issuer": "",
            "description": "",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/admin/products?error=slug+exists"


def test_edit_route_invalid_slug_redirects_with_error(client: TestClient) -> None:
    _admin_create(client)
    cookies = _login(client)
    r = client.post(
        "/admin/products/myapp/edit",
        data={
            "slug": "Bad Slug!", "name": "X",
            "key_prefix": "myapp", "jwt_issuer": "",
            "description": "",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"].startswith("/admin/products?error=")


def test_new_product_route_is_gone(client: TestClient) -> None:
    """The standalone /admin/products/new page is replaced by the modal."""
    cookies = _login(client)
    r = client.get("/admin/products/new", cookies=cookies)
    assert r.status_code == 404


def test_create_collision_redirects_to_products_list(client: TestClient) -> None:
    """Create-error redirect target moved from /admin/products/new to /admin/products."""
    _admin_create(client, slug="dup")
    cookies = _login(client)
    r = client.post(
        "/admin/products",
        data={
            "slug": "dup", "name": "Dup",
            "key_prefix": "dup",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/admin/products?error=slug+exists"
