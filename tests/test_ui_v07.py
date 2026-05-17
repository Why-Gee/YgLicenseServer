"""UI changes shipped in v0.7.1 — dashboard counter, Products tab,
customers Products column + Edit modal, Events Save-As-CSV."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _login(client: TestClient) -> dict[str, str]:
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return {"asm_ls_session": r.cookies["asm_ls_session"]}


def _csrf(cookies: dict[str, str]) -> str:
    from app.config import get_settings
    from app.security import csrf_token
    return csrf_token(get_settings().session_secret, cookies["asm_ls_session"])


def _create_product(client: TestClient, slug: str = "asm") -> None:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": slug, "name": slug.upper(), "key_prefix": slug},
    )
    assert r.status_code == 200, r.text


def _issue(client: TestClient, slug: str = "asm", email: str = "x@example.com") -> str:
    r = client.post(
        f"/v1/admin/products/{slug}/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={"email": email, "plan": "standard", "valid_days": 30, "features": {}},
    )
    assert r.status_code == 200, r.text
    return r.json()["license_id"]


# ---------- Dashboard --------------------------------------------------------

def test_dashboard_shows_customers_counter(client: TestClient) -> None:
    """Customers stat widget is rendered between Products and Active Licenses."""
    cookies = _login(client)
    _create_product(client)
    _issue(client, email="a@example.com")
    _issue(client, email="b@example.com")

    r = client.get("/admin", cookies=cookies)
    assert r.status_code == 200
    body = r.content
    # Customers label appears as a stat card.
    assert b">Customers</div>" in body
    # The four stat labels in expected nav order.
    products_at = body.find(b">Products</div>")
    customers_at = body.find(b">Customers</div>")
    active_at = body.find(b">Active Licenses</div>")
    total_at = body.find(b">Total Licenses</div>")
    assert -1 < products_at < customers_at < active_at < total_at, (
        f"order wrong: products={products_at} customers={customers_at} "
        f"active={active_at} total={total_at}"
    )


def test_dashboard_does_not_render_products_list(client: TestClient) -> None:
    """The product list moved out of the dashboard in v0.7.1 — only the
    stat widget + Recent Events remain. No bulk-delete form on / admin."""
    cookies = _login(client)
    _create_product(client)
    r = client.get("/admin", cookies=cookies)
    # The bulk-delete form for products is only on /admin/products now.
    assert b'action="/admin/products/delete"' not in r.content


# ---------- /admin/products -----------------------------------------------

def test_products_tab_lists_products(client: TestClient) -> None:
    cookies = _login(client)
    _create_product(client, slug="asm")
    _create_product(client, slug="other")
    r = client.get("/admin/products", cookies=cookies)
    assert r.status_code == 200
    assert b'<code>asm</code>' in r.content
    assert b'<code>other</code>' in r.content
    # New-product button still on this page.
    assert b'href="/admin/products/new"' in r.content


def test_products_tab_link_in_nav(client: TestClient) -> None:
    cookies = _login(client)
    r = client.get("/admin", cookies=cookies)
    assert b'href="/admin/products"' in r.content


# ---------- Customers ----------------------------------------------------

def test_customers_page_shows_products_column(client: TestClient) -> None:
    cookies = _login(client)
    _create_product(client, slug="asm")
    _create_product(client, slug="other")
    _issue(client, slug="asm", email="multi@example.com")
    _issue(client, slug="other", email="multi@example.com")
    _issue(client, slug="asm", email="single@example.com")

    r = client.get("/admin/customers", cookies=cookies)
    assert r.status_code == 200
    body = r.content
    # Header present.
    assert b">Products</th>" in body
    # Both customers listed; the multi one shows both product slugs.
    assert b"multi@example.com" in body
    assert b"single@example.com" in body


def test_customer_edit_updates_fields(client: TestClient) -> None:
    cookies = _login(client)
    _create_product(client)
    _issue(client, email="old@example.com")

    # Fetch the customer id from the DB.
    from app.db import SessionLocal
    from app.models import Customer
    with SessionLocal() as s:
        cust = s.query(Customer).filter_by(email="old@example.com").one()
        cid = cust.id

    r = client.post(
        f"/admin/customers/{cid}/edit",
        data={
            "name": "Acme", "email": "new@example.com",
            "stripe_customer_id": "cus_123", "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    assert "edited=" in r.headers["location"]

    with SessionLocal() as s:
        cust = s.query(Customer).filter_by(id=cid).one()
        assert cust.name == "Acme"
        assert cust.email == "new@example.com"
        assert cust.stripe_customer_id == "cus_123"


def test_customer_edit_rejects_email_collision(client: TestClient) -> None:
    """Two customers, can't rename one's email to the other's."""
    cookies = _login(client)
    _create_product(client)
    _issue(client, email="a@example.com")
    _issue(client, email="b@example.com")

    from app.db import SessionLocal
    from app.models import Customer
    with SessionLocal() as s:
        cid_a = s.query(Customer).filter_by(email="a@example.com").one().id

    r = client.post(
        f"/admin/customers/{cid_a}/edit",
        data={
            "name": "", "email": "b@example.com",
            "stripe_customer_id": "", "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert "error=" in r.headers["location"]

    with SessionLocal() as s:
        # Email unchanged on customer a.
        cust = s.query(Customer).filter_by(id=cid_a).one()
        assert cust.email == "a@example.com"


# ---------- Events CSV ----------------------------------------------------

def test_events_csv_download(client: TestClient) -> None:
    """Events log exports as CSV with attachment Content-Disposition so the
    browser opens its Save-As dialog."""
    cookies = _login(client)
    _create_product(client)  # generates a product:created event
    _issue(client)  # generates an issued event

    r = client.get("/admin/events.csv", cookies=cookies)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    assert "events-" in r.headers["content-disposition"]
    body = r.text
    # Header line.
    assert body.startswith("when,type,license_id,product_id,note,payload")
    # The issued event row landed.
    assert "issued" in body


def test_events_page_has_save_as_button(client: TestClient) -> None:
    """Save As button is JS-driven (showSaveFilePicker w/ download fallback);
    it fetches /admin/events.csv and writes via the user's chosen handle.
    The page no longer carries a raw <a href> to the CSV — pin the button id
    and label, and the JS reference to the endpoint."""
    cookies = _login(client)
    r = client.get("/admin/events", cookies=cookies)
    assert r.status_code == 200
    assert b'id="events-save-as"' in r.content
    assert b"Save As" in r.content
    # JS still calls the same endpoint.
    assert b"/admin/events.csv" in r.content
