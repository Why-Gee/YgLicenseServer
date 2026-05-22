"""Rate limiting on abuse-sensitive endpoints.

T1-B: /v1/check capped at 60/min per IP; /admin/login capped at 10/min per
IP. Both should respond 429 once the bucket is empty.

slowapi keys on `app.rate_limit.client_ip`, which since v0.22 returns
`request.client.host` unconditionally — no X-Forwarded-For parsing
(Caddy appends rather than overwrites, so the leftmost XFF entry was
attacker-controlled). The TestClient peer is `testclient`, so every
test in this file shares one bucket — exactly what we want for "ten
requests in a row from one client" coverage.
"""
from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def _reload_rate_limit_state() -> None:
    """Tests share the in-memory slowapi limiter; reload the modules so each
    test starts with an empty bucket. Must happen AFTER the conftest reload
    chain (which itself imports app.main fresh) so the live `limiter` is the
    one our tests will trigger."""
    import app.rate_limit as rl
    importlib.reload(rl)


def _create_product(client: TestClient) -> dict:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200, r.text
    return r.json()


def _issue(client: TestClient) -> str:
    r = client.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={"email": "x@example.com", "plan": "standard", "valid_days": 30},
    )
    assert r.status_code == 200, r.text
    return r.json()["key"]


def test_check_rate_limit_429_after_60(client: TestClient) -> None:
    """Hammering /v1/check from one IP eventually trips a 429. We bound
    the limit (60/min) but slowapi's moving-window strategy can land the
    bucket anywhere within the minute, so we just assert that the cap is
    real -- not the exact 200 count, which would couple the test to
    slowapi's window math."""
    _create_product(client)
    key = _issue(client)
    body = {"key": key, "install_id": "i1", "version": "1.0.0"}
    statuses = []
    for _ in range(70):
        r = client.post("/v1/check", json=body)
        statuses.append(r.status_code)
    assert 429 in statuses, f"expected at least one 429 in 70 calls; got {statuses}"
    # And the cap should be at most the configured limit.
    assert statuses.count(200) <= 60


def test_check_rate_limit_first_call_allowed(client: TestClient) -> None:
    """A single /v1/check from a cold bucket must succeed -- the limiter
    can't be so aggressive it 429s legitimate first contact."""
    _create_product(client)
    key = _issue(client)
    r = client.post(
        "/v1/check", json={"key": key, "install_id": "i1", "version": "1.0.0"},
    )
    assert r.status_code == 200, r.text


def test_login_rate_limit_429_after_10(client: TestClient) -> None:
    """Hammering /admin/login from one IP eventually trips a 429."""
    statuses = []
    for _ in range(15):
        r = client.post(
            "/admin/login",
            data={"token": "wrong"},
            follow_redirects=False,
        )
        statuses.append(r.status_code)
    assert 429 in statuses, f"expected at least one 429 in 15 calls; got {statuses}"
    # First call must succeed (303 redirect to /admin/login?error=invalid).
    assert statuses[0] == 303
