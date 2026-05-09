"""Customer.name persistence + UI exposure tests.

The optional Customer.name column is wired through the issue form, the
edit form, and the JSON admin API. UI renders it as a separate column
in the per-product license list and as an input in the issue/edit
modal.
"""
from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    db_path = tmp_path / "license.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ADMIN_TOKEN", "test-admin")
    monkeypatch.setenv("SESSION_SECRET", "test-session")
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.delenv("RESEND_API_KEY", raising=False)

    import app.config as cfg
    import app.db as db
    importlib.reload(cfg)
    importlib.reload(db)
    import app.webhooks as wh
    importlib.reload(wh)
    import app.api as api_mod
    importlib.reload(api_mod)
    import app.admin_ui as ui_mod
    importlib.reload(ui_mod)
    import app.main as m
    importlib.reload(m)
    db.init_db()
    return TestClient(m.app)


def _login(client: TestClient) -> dict[str, str]:
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return {"asm_ls_session": r.cookies["asm_ls_session"]}


def _create_product(client: TestClient) -> None:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200, r.text


def _read_customer_name_by_email(email: str) -> str | None:
    import app.db as db_mod
    from app.models import Customer
    with db_mod.SessionLocal() as session:
        c = session.query(Customer).filter_by(email=email).one()
        return c.name


def test_issue_form_persists_customer_name(client: TestClient) -> None:
    _create_product(client)
    cookies = _login(client)
    r = client.post(
        "/admin/products/asm/licenses",
        data={
            "email": "buyer@example.com",
            "customer_name": "Acme Animal Shelter",
            "plan": "standard",
            "max_users": "10",
            "valid_days": "30",
            "features_json": "{}",
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    assert _read_customer_name_by_email("buyer@example.com") == "Acme Animal Shelter"


def test_issue_form_blank_name_stays_null(client: TestClient) -> None:
    _create_product(client)
    cookies = _login(client)
    r = client.post(
        "/admin/products/asm/licenses",
        data={
            "email": "buyer@example.com",
            "plan": "standard",
            "max_users": "10",
            "valid_days": "30",
            "features_json": "{}",
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert _read_customer_name_by_email("buyer@example.com") is None


def test_issue_form_overwrites_existing_name_when_supplied(client: TestClient) -> None:
    """Re-issuing for the same email with a non-empty name updates the
    existing customer row. Empty name leaves it alone (separate test)."""
    _create_product(client)
    cookies = _login(client)
    base = {
        "email": "buyer@example.com", "plan": "standard",
        "max_users": "10", "valid_days": "30", "features_json": "{}",
    }
    client.post(
        "/admin/products/asm/licenses",
        data={**base, "customer_name": "Initial Name"},
        cookies=cookies, follow_redirects=False,
    )
    client.post(
        "/admin/products/asm/licenses",
        data={**base, "customer_name": "Updated Name"},
        cookies=cookies, follow_redirects=False,
    )
    assert _read_customer_name_by_email("buyer@example.com") == "Updated Name"


def test_issue_form_blank_name_does_not_wipe_existing(client: TestClient) -> None:
    _create_product(client)
    cookies = _login(client)
    base = {
        "email": "buyer@example.com", "plan": "standard",
        "max_users": "10", "valid_days": "30", "features_json": "{}",
    }
    client.post(
        "/admin/products/asm/licenses",
        data={**base, "customer_name": "Keep Me"},
        cookies=cookies, follow_redirects=False,
    )
    # Second issue without customer_name field at all -- existing name stays.
    client.post(
        "/admin/products/asm/licenses",
        data=base,
        cookies=cookies, follow_redirects=False,
    )
    assert _read_customer_name_by_email("buyer@example.com") == "Keep Me"


def test_edit_form_updates_customer_name(client: TestClient) -> None:
    """The edit modal exposes Customer Name as an editable field;
    submitting overwrites (empty clears, non-empty replaces)."""
    _create_product(client)
    cookies = _login(client)
    r = client.post(
        "/admin/products/asm/licenses",
        data={
            "email": "buyer@example.com",
            "customer_name": "Original",
            "plan": "standard",
            "max_users": "10",
            "valid_days": "30",
            "features_json": "{}",
        },
        cookies=cookies, follow_redirects=False,
    )
    lid = r.headers["location"].rsplit("issued=", 1)[1]

    # Pull the license to get its current valid_until for the edit payload.
    import app.db as db_mod
    from app.models import License
    with db_mod.SessionLocal() as session:
        lic = session.query(License).filter_by(id=lid).one()
        valid_until_str = lic.valid_until.strftime("%Y-%m-%d")
        plan, max_users = lic.plan, lic.max_users

    # Rename via /edit.
    r = client.post(
        f"/admin/licenses/{lid}/edit",
        data={
            "plan": plan, "max_users": str(max_users),
            "valid_until": valid_until_str, "features_json": "{}",
            "customer_name": "Renamed Customer",
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert _read_customer_name_by_email("buyer@example.com") == "Renamed Customer"

    # Clear via blank submission.
    r = client.post(
        f"/admin/licenses/{lid}/edit",
        data={
            "plan": plan, "max_users": str(max_users),
            "valid_until": valid_until_str, "features_json": "{}",
            "customer_name": "",
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert _read_customer_name_by_email("buyer@example.com") is None


def test_product_detail_renders_name_column_and_modal_field(client: TestClient) -> None:
    """The product page must render the Customer Name column header, the
    per-row value, and the modal input."""
    _create_product(client)
    cookies = _login(client)
    client.post(
        "/admin/products/asm/licenses",
        data={
            "email": "buyer@example.com",
            "customer_name": "Acme Animal Shelter",
            "plan": "standard",
            "max_users": "10",
            "valid_days": "30",
            "features_json": "{}",
        },
        cookies=cookies, follow_redirects=False,
    )
    r = client.get("/admin/products/asm", cookies=cookies)
    assert r.status_code == 200
    body = r.content
    # Header changes: Customer -> Customer Name + Customer Email.
    assert b"<th>Customer Name</th>" in body
    assert b"<th>Customer Email</th>" in body
    # Row value present.
    assert b"Acme Animal Shelter" in body
    # Modal field present.
    assert b'id="lm-customer-name"' in body
    assert b'name="customer_name"' in body
    # JSON payload exposes the field for modal pre-fill.
    assert b'"customer_name": "Acme Animal Shelter"' in body


def test_admin_list_licenses_includes_customer_name(client: TestClient) -> None:
    _create_product(client)
    cookies = _login(client)
    client.post(
        "/admin/products/asm/licenses",
        data={
            "email": "buyer@example.com",
            "customer_name": "Acme",
            "plan": "standard",
            "max_users": "10",
            "valid_days": "30",
            "features_json": "{}",
        },
        cookies=cookies, follow_redirects=False,
    )
    r = client.get(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
    )
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["customer"] == "buyer@example.com"
    assert rows[0]["customer_name"] == "Acme"


def test_v1_admin_issue_persists_name(client: TestClient) -> None:
    _create_product(client)
    r = client.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={
            "email": "api@example.com",
            "name": "Via API",
            "plan": "standard",
            "max_users": 5,
            "valid_days": 30,
        },
    )
    assert r.status_code == 200, r.text
    assert _read_customer_name_by_email("api@example.com") == "Via API"

    r = client.get(
        "/v1/admin/customers",
        headers={"Authorization": "Bearer test-admin"},
    )
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["email"] == "api@example.com"
    assert rows[0]["name"] == "Via API"
