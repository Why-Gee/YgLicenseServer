"""Customer.name persistence + UI exposure tests.

The optional Customer.name column is wired through the issue form, the
edit form, and the JSON admin API. UI renders it as a separate column
in the per-product license list and as an input in the issue/edit
modal.
"""
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


def _issue_form(cookies, **fields) -> dict:
    """Build a license-issue form dict with the CSRF token baked in."""
    return {**fields, "csrf_token": _csrf(cookies)}


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
        data=_issue_form(
            cookies,
            email="buyer@example.com",
            customer_name="Acme Animal Shelter",
            plan="standard", max_users="10", valid_days="30",
            features_json="{}",
        ),
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    assert _read_customer_name_by_email("buyer@example.com") == "Acme Animal Shelter"


def test_issue_form_blank_name_stays_null(client: TestClient) -> None:
    _create_product(client)
    cookies = _login(client)
    r = client.post(
        "/admin/products/asm/licenses",
        data=_issue_form(
            cookies,
            email="buyer@example.com",
            plan="standard", max_users="10", valid_days="30",
            features_json="{}",
        ),
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert _read_customer_name_by_email("buyer@example.com") is None


def test_issue_form_ignores_name_for_existing_customer(client: TestClient) -> None:
    """A Customer is tenant-wide (one row per email across all products on
    this server). Re-issuing for an existing email MUST NOT silently rename
    the customer -- otherwise issuing a license for Product B would clobber
    the name set during issuance for Product A. Rename via
    /admin/customers/{id}/edit instead."""
    _create_product(client)
    cookies = _login(client)
    base = {
        "email": "buyer@example.com", "plan": "standard",
        "max_users": "10", "valid_days": "30", "features_json": "{}",
        "csrf_token": _csrf(cookies),
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
    # Name from the SECOND issue is ignored -- customer already existed.
    assert _read_customer_name_by_email("buyer@example.com") == "Initial Name"


def test_issue_form_blank_name_does_not_wipe_existing(client: TestClient) -> None:
    _create_product(client)
    cookies = _login(client)
    base = {
        "email": "buyer@example.com", "plan": "standard",
        "max_users": "10", "valid_days": "30", "features_json": "{}",
        "csrf_token": _csrf(cookies),
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


def test_edit_form_ignores_customer_name_field(client: TestClient) -> None:
    """License-edit must NOT mutate the linked Customer's name even if the
    form payload includes one (e.g. crafted directly, or from a stale modal).
    The Customer rename lives at /admin/customers/{id}/edit."""
    _create_product(client)
    cookies = _login(client)
    r = client.post(
        "/admin/products/asm/licenses",
        data=_issue_form(
            cookies,
            email="buyer@example.com", customer_name="Original",
            plan="standard", max_users="10", valid_days="30",
            features_json="{}",
        ),
        cookies=cookies, follow_redirects=False,
    )
    lid = r.headers["location"].rsplit("issued=", 1)[1]

    import app.db as db_mod
    from app.models import License
    with db_mod.SessionLocal() as session:
        lic = session.query(License).filter_by(id=lid).one()
        valid_until_str = lic.valid_until.strftime("%Y-%m-%d")
        plan, max_users = lic.plan, lic.max_users

    # Even if a crafted POST includes customer_name, /edit ignores it.
    r = client.post(
        f"/admin/licenses/{lid}/edit",
        data={
            "plan": plan, "max_users": str(max_users),
            "valid_until": valid_until_str, "features_json": "{}",
            "customer_name": "Hijacked Name",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert _read_customer_name_by_email("buyer@example.com") == "Original"


def test_customer_lookup_returns_existing(client: TestClient) -> None:
    """/admin/customers/lookup powers the issue-modal's email-blur check:
    when the email is taken, the modal locks the name field + shows a link
    to the proper rename path. Cookie-auth, JSON envelope."""
    _create_product(client)
    cookies = _login(client)
    client.post(
        "/admin/products/asm/licenses",
        data=_issue_form(
            cookies,
            email="buyer@example.com", customer_name="Initial Name",
            plan="standard", max_users="10", valid_days="30",
            features_json="{}",
        ),
        cookies=cookies, follow_redirects=False,
    )
    r = client.get(
        "/admin/customers/lookup?email=buyer@example.com", cookies=cookies,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["exists"] is True
    assert data["name"] == "Initial Name"
    assert data["id"]


def test_customer_lookup_returns_not_exists_for_new_email(client: TestClient) -> None:
    cookies = _login(client)
    r = client.get(
        "/admin/customers/lookup?email=nobody@example.test", cookies=cookies,
    )
    assert r.status_code == 200
    assert r.json() == {"exists": False}


def test_customer_lookup_requires_login(client: TestClient) -> None:
    """No cookie -> redirect to /admin/login like every other /admin route."""
    r = client.get(
        "/admin/customers/lookup?email=x@example.com", follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/admin/login"


def test_customer_edit_route_renames(client: TestClient) -> None:
    """The proper rename path: POST /admin/customers/{id}/edit with name."""
    _create_product(client)
    cookies = _login(client)
    client.post(
        "/admin/products/asm/licenses",
        data=_issue_form(
            cookies,
            email="buyer@example.com", customer_name="Original",
            plan="standard", max_users="10", valid_days="30",
            features_json="{}",
        ),
        cookies=cookies, follow_redirects=False,
    )

    import app.db as db_mod
    from app.models import Customer
    with db_mod.SessionLocal() as s:
        cid = s.query(Customer).filter_by(email="buyer@example.com").one().id

    r = client.post(
        f"/admin/customers/{cid}/edit",
        data={
            "email": "buyer@example.com",
            "name": "Properly Renamed",
            "stripe_customer_id": "",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    assert _read_customer_name_by_email("buyer@example.com") == "Properly Renamed"


def test_product_detail_renders_name_column_and_modal_field(client: TestClient) -> None:
    """The product page must render the Customer Name column header, the
    per-row value, and the modal input."""
    _create_product(client)
    cookies = _login(client)
    client.post(
        "/admin/products/asm/licenses",
        data=_issue_form(
            cookies,
            email="buyer@example.com",
            customer_name="Acme Animal Shelter",
            plan="standard", max_users="10", valid_days="30",
            features_json="{}",
        ),
        cookies=cookies, follow_redirects=False,
    )
    r = client.get("/admin/products/asm", cookies=cookies)
    assert r.status_code == 200
    body = r.content
    # Header changes: Customer -> Customer Name + Customer Email. Headers
    # carry data-sort-key attributes (sortable tables), so match just the
    # label text inside any <th ...>.
    assert b">Customer Name</th>" in body
    assert b">Customer Email</th>" in body
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
        data=_issue_form(
            cookies,
            email="buyer@example.com", customer_name="Acme",
            plan="standard", max_users="10", valid_days="30",
            features_json="{}",
        ),
        cookies=cookies, follow_redirects=False,
    )
    r = client.get(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
    )
    assert r.status_code == 200
    body = r.json()
    rows = body["items"]
    assert body["next_cursor"] is None
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
    body = r.json()
    rows = body["items"]
    assert body["next_cursor"] is None
    assert len(rows) == 1
    assert rows[0]["email"] == "api@example.com"
    assert rows[0]["name"] == "Via API"
