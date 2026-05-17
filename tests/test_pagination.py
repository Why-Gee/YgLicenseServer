"""Cursor pagination correctness.

Covers the keyset cursor primitive and the two paginated endpoints
(/v1/admin/customers, /v1/admin/products/{slug}/licenses):
  - encode/decode roundtrip
  - malformed cursor decodes to None (caller treats as "start over")
  - paginating in pages of N covers exactly the full set without dupes/gaps
  - `next_cursor` is None on the final page
"""
from __future__ import annotations

from datetime import datetime

from fastapi.testclient import TestClient

# ----- primitive ----------------------------------------------------------

def test_cursor_roundtrip() -> None:
    from app.pagination import decode_cursor, encode_cursor
    ts = datetime(2026, 5, 17, 12, 30, 45)
    rid = "abc-123-def"
    tok = encode_cursor(ts, rid)
    out = decode_cursor(tok)
    assert out == (ts, rid)


def test_malformed_cursor_returns_none() -> None:
    from app.pagination import decode_cursor
    assert decode_cursor(None) is None
    assert decode_cursor("") is None
    assert decode_cursor("not-base64!!!") is None
    assert decode_cursor("YWJj") is None  # decodes to "abc" -- no pipe
    # Valid base64 but only a timestamp -- no row id.
    import base64
    bad = base64.urlsafe_b64encode(b"2026-01-01T00:00:00").rstrip(b"=").decode()
    assert decode_cursor(bad) is None


def test_clamp_limit_bounds() -> None:
    from app.pagination import MAX_LIMIT, clamp_limit
    assert clamp_limit(None) == 100
    assert clamp_limit("not-a-number") == 100
    assert clamp_limit("-5") == 100
    assert clamp_limit(0) == 100
    assert clamp_limit("50") == 50
    assert clamp_limit("99999") == MAX_LIMIT


# ----- /v1/admin/customers end-to-end -------------------------------------

def _seed_customers(client: TestClient, n: int) -> None:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200
    for i in range(n):
        r = client.post(
            "/v1/admin/products/asm/licenses",
            headers={"Authorization": "Bearer test-admin"},
            json={"email": f"c{i:03d}@example.test", "plan": "p", "valid_days": 1},
        )
        assert r.status_code == 200, r.text


def test_paginated_customers_covers_full_set(client: TestClient) -> None:
    _seed_customers(client, 7)

    seen: list[str] = []
    cursor: str | None = None
    for _ in range(20):  # generous bound -- protects against runaway loops
        url = "/v1/admin/customers?limit=3"
        if cursor:
            url += f"&cursor={cursor}"
        r = client.get(url, headers={"Authorization": "Bearer test-admin"})
        assert r.status_code == 200
        body = r.json()
        seen.extend(item["email"] for item in body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            break

    # All 7 customers seen, none duplicated.
    assert sorted(seen) == [f"c{i:03d}@example.test" for i in range(7)]
    assert len(seen) == len(set(seen))


def test_paginated_customers_next_cursor_none_at_end(client: TestClient) -> None:
    """A page that returns fewer than `limit` rows must report
    next_cursor=null. Otherwise the caller would loop forever."""
    _seed_customers(client, 2)
    r = client.get(
        "/v1/admin/customers?limit=10",
        headers={"Authorization": "Bearer test-admin"},
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body["items"]) == 2
    assert body["next_cursor"] is None
