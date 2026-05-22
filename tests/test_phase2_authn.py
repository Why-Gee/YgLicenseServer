"""Phase 2 authn + crypto hardening — TDD tests for H1, H2, H3."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _create_product(client: TestClient, slug: str = "asm") -> None:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": slug, "name": slug.upper(), "key_prefix": slug},
    )
    assert r.status_code == 200, r.text


def _issue(client: TestClient, slug: str = "asm") -> str:
    r = client.post(
        f"/v1/admin/products/{slug}/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={
            "email": "alice@example.com", "plan": "standard", "valid_days": 30,
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["key"]


# ---------- H1: XFF ignored, request.client.host wins -----------------------


def test_client_ip_hash_ignores_xff(monkeypatch):
    """_client_ip_hash must return SHA-256 of request.client.host,
    even when X-Forwarded-For is present and the peer is loopback.
    Direct unit test against the helper — TestClient's peer doesn't
    simulate the loopback condition the old branch was triggered by."""
    from app.routers.api import _client_ip_hash
    import hashlib

    class _FakeRequest:
        class client:
            host = "127.0.0.1"
        headers = {"x-forwarded-for": "10.20.30.40"}

    got = _client_ip_hash(_FakeRequest())
    assert got == hashlib.sha256(b"127.0.0.1").hexdigest(), (
        f"_client_ip_hash returned {got!r}; expected SHA-256 of '127.0.0.1'. "
        f"XFF parsing not dropped."
    )


def test_rate_limit_client_ip_ignores_xff():
    """app.rate_limit.client_ip must also ignore XFF."""
    from app.rate_limit import client_ip

    class _FakeRequest:
        class client:
            host = "127.0.0.1"
        headers = {"x-forwarded-for": "10.20.30.40"}

    assert client_ip(_FakeRequest()) == "127.0.0.1"


# ---------- H2: JWT kid claim (aud deferred to v1.0) -----------------------


def test_jwt_carries_kid_claim(client):
    """Issued JWTs must carry kid (product id, survives slug rename).
    aud is intentionally NOT added in v0.22 because pyjwt validates aud
    whenever it's present in a token, which would break every client
    decoding without `audience=`. aud lands in v1.0 with the other
    breaking changes."""
    _create_product(client)
    key = _issue(client)
    r = client.post(
        "/v1/check",
        json={"key": key, "install_id": "ii-1", "version": "1.0"},
    )
    assert r.status_code == 200, r.text
    token = r.json()["jwt"]

    import jwt as pyjwt
    # Decode without signature verification — we just want the payload.
    claims = pyjwt.decode(token, options={"verify_signature": False})
    assert "kid" in claims, f"jwt missing kid: {claims}"
    # kid is an opaque UUID — assert shape, not value.
    assert isinstance(claims["kid"], str) and len(claims["kid"]) >= 8, claims["kid"]
    # Explicit anti-regression: aud must NOT be added today (breaking change).
    assert "aud" not in claims, (
        f"aud present in v0.22 token; defer to v1.0 with breaking changes: {claims}"
    )
