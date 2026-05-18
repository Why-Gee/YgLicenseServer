"""CSV export endpoints (v0.14).

Verifies:
  - Bearer auth required (401 without token).
  - 200 + correct CSV header for each endpoint.
  - One row per record in the underlying table.
  - Content-Disposition asks the browser to download a file.
"""
from __future__ import annotations

import csv
import io


def _setup_product(client) -> str:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200
    r = client.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={
            "email": "alice@example.com", "name": "Alice",
            "plan": "standard", "valid_days": 30,
        },
    )
    assert r.status_code == 200
    r = client.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={
            "email": "bob@example.com", "name": "Bob",
            "plan": "pro", "valid_days": 365,
        },
    )
    assert r.status_code == 200
    return "asm"


def _csv_rows(body: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(body)))


def test_customers_csv_requires_auth(client) -> None:
    r = client.get("/v1/admin/exports/customers.csv")
    assert r.status_code in (401, 403)


def test_customers_csv_returns_all_rows(client) -> None:
    _setup_product(client)
    r = client.get(
        "/v1/admin/exports/customers.csv",
        headers={"Authorization": "Bearer test-admin"},
    )
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "customers.csv" in r.headers["content-disposition"]
    rows = _csv_rows(r.text)
    assert rows[0] == [
        "id", "email", "name", "stripe_customer_id", "license_count", "created_at",
    ]
    emails = {r[1] for r in rows[1:]}
    assert emails == {"alice@example.com", "bob@example.com"}


def test_licenses_csv_per_product(client) -> None:
    _setup_product(client)
    r = client.get(
        "/v1/admin/exports/products/asm/licenses.csv",
        headers={"Authorization": "Bearer test-admin"},
    )
    assert r.status_code == 200
    rows = _csv_rows(r.text)
    assert rows[0] == [
        "id", "key", "plan", "status", "max_users", "valid_until",
        "customer_email", "customer_name", "webhook_url", "created_at",
    ]
    plans = {r[2] for r in rows[1:]}
    assert plans == {"standard", "pro"}


def test_licenses_csv_404_for_unknown_product(client) -> None:
    r = client.get(
        "/v1/admin/exports/products/nope/licenses.csv",
        headers={"Authorization": "Bearer test-admin"},
    )
    assert r.status_code == 404


def test_events_csv_per_product(client) -> None:
    _setup_product(client)
    r = client.get(
        "/v1/admin/exports/products/asm/events.csv",
        headers={"Authorization": "Bearer test-admin"},
    )
    assert r.status_code == 200
    rows = _csv_rows(r.text)
    assert rows[0] == [
        "id", "created_at", "type", "subject_kind", "subject_id",
        "license_id", "payload", "note",
    ]
    # Each issued license generated an "issued" event.
    types = [r[2] for r in rows[1:]]
    assert types.count("issued") == 2
