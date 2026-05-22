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


# ---------- H3: KEK required gate ------------------------------------------


def _reload_config_and_keystore() -> None:
    """Pick up new env vars by rebuilding the cached Settings + keystore."""
    import importlib
    import app.config as cfg
    importlib.reload(cfg)
    import app.keystore as ks
    importlib.reload(ks)


def test_require_kek_unset_keeps_legacy_plaintext_passthrough(monkeypatch):
    """Default deploys without LICENSE_SERVER_REQUIRE_KEK keep the current
    'plaintext passthrough' behaviour for backwards compatibility."""
    monkeypatch.setenv("LICENSE_KEY_ENCRYPTION_KEY", "")
    monkeypatch.delenv("LICENSE_SERVER_REQUIRE_KEK", raising=False)
    _reload_config_and_keystore()
    from app.keystore import encrypt_secret
    assert encrypt_secret("plain") == "plain"


def test_require_kek_set_refuses_to_persist_plaintext(monkeypatch):
    """With LICENSE_SERVER_REQUIRE_KEK=1 and no KEK, encrypt_secret raises
    instead of silently passing plaintext through."""
    monkeypatch.setenv("LICENSE_KEY_ENCRYPTION_KEY", "")
    monkeypatch.setenv("LICENSE_SERVER_REQUIRE_KEK", "1")
    _reload_config_and_keystore()
    from app.keystore import encrypt_secret
    import pytest
    with pytest.raises(RuntimeError, match="KEK required"):
        encrypt_secret("plain")


def test_require_kek_set_with_valid_key_works_normally(monkeypatch):
    """LICENSE_SERVER_REQUIRE_KEK=1 + a valid KEK = normal Fernet wrapping."""
    from cryptography.fernet import Fernet
    kek = Fernet.generate_key().decode()
    monkeypatch.setenv("LICENSE_KEY_ENCRYPTION_KEY", kek)
    monkeypatch.setenv("LICENSE_SERVER_REQUIRE_KEK", "1")
    _reload_config_and_keystore()
    from app.keystore import encrypt_secret, decrypt_secret, is_encrypted
    out = encrypt_secret("hello")
    assert is_encrypted(out)
    assert decrypt_secret(out) == "hello"


def test_boot_validator_exits_when_kek_required_and_unset(monkeypatch):
    """_validate_secrets_at_boot() must sys.exit(78) when REQUIRE_KEK is set
    without a KEK present. Other branches (admin_token/session_secret missing)
    already use the same EX_CONFIG exit code; this just adds one more trigger."""
    monkeypatch.setenv("ADMIN_TOKEN", "x")
    monkeypatch.setenv("SESSION_SECRET", "y")
    monkeypatch.setenv("LICENSE_KEY_ENCRYPTION_KEY", "")
    monkeypatch.setenv("LICENSE_SERVER_REQUIRE_KEK", "1")
    _reload_config_and_keystore()
    import importlib
    import app.main as main_mod
    importlib.reload(main_mod)
    import pytest
    with pytest.raises(SystemExit) as exc:
        main_mod._validate_secrets_at_boot()
    assert exc.value.code == 78
