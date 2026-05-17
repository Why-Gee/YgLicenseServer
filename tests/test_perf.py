"""Query-count regressions for the admin list endpoints.

The aggregate-count refactor (v0.10) replaced per-row `len(p.licenses)` lazy
loads with a single GROUP BY on each list endpoint. These tests catch a
regression back to N+1 by counting SQL statements executed during the call.
"""
from __future__ import annotations

import contextlib

from fastapi.testclient import TestClient
from sqlalchemy import event


@contextlib.contextmanager
def _count_queries():
    """Yield a list that fills with every emitted SQL statement during the
    block. Uses sqlalchemy's `before_cursor_execute` event so we capture even
    statements issued by lazy-load attribute access."""
    seen: list[str] = []
    from sqlalchemy.engine import Engine

    def _cb(_conn, _cursor, statement, _params, _ctx, _exec):
        seen.append(statement)

    event.listen(Engine, "before_cursor_execute", _cb)
    try:
        yield seen
    finally:
        event.remove(Engine, "before_cursor_execute", _cb)


def _create_product(client: TestClient, slug: str) -> None:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": slug, "name": slug.upper(), "key_prefix": slug},
    )
    assert r.status_code == 200, r.text


def _issue(client: TestClient, slug: str, email: str) -> None:
    r = client.post(
        f"/v1/admin/products/{slug}/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={"email": email, "plan": "standard", "max_users": 1, "valid_days": 30},
    )
    assert r.status_code == 200, r.text


def test_admin_list_products_is_not_n_plus_1(client: TestClient) -> None:
    """List 5 products with varied license counts. The endpoint must emit a
    bounded number of statements -- not one extra SELECT per product."""
    for i in range(5):
        _create_product(client, f"p{i}")
        for j in range(i):
            _issue(client, f"p{i}", f"u{i}_{j}@example.test")

    with _count_queries() as q:
        r = client.get(
            "/v1/admin/products",
            headers={"Authorization": "Bearer test-admin"},
        )
    assert r.status_code == 200
    body = r.json()
    # /v1/admin/products stays a list shape (small fixed-size set); only the
    # paginated customer/license endpoints return {items, next_cursor}.
    assert len(body) == 5
    counts = {p["slug"]: p["license_count"] for p in body}
    assert counts == {"p0": 0, "p1": 1, "p2": 2, "p3": 3, "p4": 4}

    # Without the aggregate query, 5 products would each trigger one extra
    # SELECT for their licenses (5 N+1 + 1 base = 6). The new path is one
    # aggregate join, so we cap well below that.
    assert len(q) <= 3, f"too many SQL statements emitted: {len(q)}: {q}"


def test_admin_list_customers_is_not_n_plus_1(client: TestClient) -> None:
    """Same shape, customer side."""
    _create_product(client, "asm")
    for i in range(5):
        _issue(client, "asm", f"user{i}@example.test")

    with _count_queries() as q:
        r = client.get(
            "/v1/admin/customers",
            headers={"Authorization": "Bearer test-admin"},
        )
    assert r.status_code == 200
    body = r.json()
    rows = body["items"]
    assert len(rows) == 5
    assert all(r["license_count"] == 1 for r in rows)
    # Cursor pagination is one base query; cap at 3 to allow slight wiggle.
    assert len(q) <= 3, f"too many SQL statements emitted: {len(q)}: {q}"
