"""Phase 4 at-rest key hashing — TDD tests for pepper config + helpers."""
from __future__ import annotations


def _reload_config() -> None:
    import importlib
    import app.config as cfg
    importlib.reload(cfg)


# ---------- pepper env var --------------------------------------------------


def test_license_key_pepper_unset_default(monkeypatch):
    """Default deploys without LICENSE_KEY_PEPPER have an empty pepper."""
    monkeypatch.delenv("LICENSE_KEY_PEPPER", raising=False)
    _reload_config()
    from app.config import get_settings
    assert get_settings().license_key_pepper == ""


def test_license_key_pepper_set_from_env(monkeypatch):
    """Setting LICENSE_KEY_PEPPER populates the Settings field."""
    monkeypatch.setenv("LICENSE_KEY_PEPPER", "test-pepper-32bytes-base64encoded=")
    _reload_config()
    from app.config import get_settings
    assert get_settings().license_key_pepper == "test-pepper-32bytes-base64encoded="


# ---------- hash_key + make_display helpers ---------------------------------


def test_hash_key_deterministic(monkeypatch):
    """Same input + pepper always produces same output (deterministic lookup)."""
    monkeypatch.setenv("LICENSE_KEY_PEPPER", "test-pepper-1234567890")
    _reload_config()
    import importlib
    import app.license_keys as lk
    importlib.reload(lk)
    a = lk.hash_key("asm_abc123")
    b = lk.hash_key("asm_abc123")
    assert a == b
    assert len(a) == 64  # blake2b-256 hex = 64 chars


def test_hash_key_different_pepper_yields_different_hash(monkeypatch):
    """Pepper affects the hash output — DB dump without pepper is useless."""
    monkeypatch.setenv("LICENSE_KEY_PEPPER", "pepper-A")
    _reload_config()
    import importlib
    import app.license_keys as lk
    importlib.reload(lk)
    h_a = lk.hash_key("asm_abc123")

    monkeypatch.setenv("LICENSE_KEY_PEPPER", "pepper-B")
    _reload_config()
    importlib.reload(lk)
    h_b = lk.hash_key("asm_abc123")
    assert h_a != h_b


def test_hash_key_refuses_when_pepper_unset(monkeypatch):
    """Calling hash_key without a pepper configured raises; the server must
    be configured before it can compute hashes that match the DB."""
    monkeypatch.delenv("LICENSE_KEY_PEPPER", raising=False)
    _reload_config()
    import importlib
    import app.license_keys as lk
    importlib.reload(lk)
    import pytest
    with pytest.raises(RuntimeError, match="LICENSE_KEY_PEPPER"):
        lk.hash_key("asm_abc123")


def test_make_display_format(monkeypatch):
    """key_display = <prefix>_<first6>…<last4>. Always safe to show in UI."""
    monkeypatch.setenv("LICENSE_KEY_PEPPER", "x")
    _reload_config()
    import importlib
    import app.license_keys as lk
    importlib.reload(lk)
    # 32-char tail after the prefix.
    result = lk.make_display("asm_abcDEF1234567890qwertyuiopAS")
    assert result == "asm_abcDEF…opAS"
    # Shorter key still works.
    short = lk.make_display("xy_aB1234")
    # 6 chars + last 4 = 10 chars; the key body is "aB1234" (6 chars).
    # last 4 == "1234" which overlaps the first 6; format still applies cleanly.
    assert short.startswith("xy_") and "…" in short


# ---------- boot validator --------------------------------------------------


def test_boot_validator_exits_when_kek_required_and_pepper_unset(monkeypatch):
    """LICENSE_SERVER_REQUIRE_KEK=1 + LICENSE_KEY_PEPPER unset → sys.exit(78)."""
    monkeypatch.setenv("ADMIN_TOKEN", "x")
    monkeypatch.setenv("SESSION_SECRET", "y")
    from cryptography.fernet import Fernet
    monkeypatch.setenv("LICENSE_KEY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("LICENSE_SERVER_REQUIRE_KEK", "1")
    monkeypatch.delenv("LICENSE_KEY_PEPPER", raising=False)
    _reload_config()
    import importlib
    import app.main as main_mod
    importlib.reload(main_mod)
    import pytest
    with pytest.raises(SystemExit) as exc:
        main_mod._validate_secrets_at_boot()
    assert exc.value.code == 78


# ---------- schema -----------------------------------------------------------


def test_license_model_has_key_hash_and_key_display_columns(monkeypatch):
    """ORM model defines the new columns."""
    monkeypatch.setenv("LICENSE_KEY_PEPPER", "x")
    _reload_config()
    import importlib
    import app.models
    importlib.reload(app.models)
    cols = {c.name for c in app.models.License.__table__.columns}
    assert "key_hash" in cols
    assert "key_display" in cols


# ---------- issuance writes hash + display ----------------------------------


def test_admin_issue_populates_hash_and_display(make_client, monkeypatch):
    from cryptography.fernet import Fernet
    c = make_client(
        LICENSE_KEY_PEPPER="testpepper" * 4,
        LICENSE_KEY_ENCRYPTION_KEY=Fernet.generate_key().decode(),
    )
    r = c.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200
    r = c.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={"email": "alice@example.com", "plan": "standard", "valid_days": 30},
    )
    assert r.status_code == 200
    plaintext = r.json()["key"]
    assert plaintext.startswith("asm_")
    from app.db import SessionLocal
    from app.models import License
    from app.license_keys import hash_key, make_display
    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=r.json()["license_id"]).one()
        assert lic.key_hash == hash_key(plaintext)
        assert lic.key_display == make_display(plaintext)
        assert lic.key == plaintext  # plaintext STILL stored in v1.0 (deprecated)


def test_migration_backfills_key_hash_and_key_display(make_client, monkeypatch):
    """After upgrade, every existing license row has key_hash + key_display
    populated from the plaintext key (using the configured pepper)."""
    from cryptography.fernet import Fernet
    monkeypatch.setenv("LICENSE_KEY_PEPPER", "deadbeef" * 4)
    monkeypatch.setenv("LICENSE_KEY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    c = make_client(
        LICENSE_KEY_PEPPER="deadbeef" * 4,
        LICENSE_KEY_ENCRYPTION_KEY=Fernet.generate_key().decode(),
    )
    # Issue a license so we have a row in the table.
    r = c.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200
    r = c.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={"email": "alice@example.com", "plan": "standard", "valid_days": 30},
    )
    assert r.status_code == 200
    plaintext = r.json()["key"]
    # Confirm the row has hash + display populated.
    from app.db import SessionLocal
    from app.models import License
    from app.license_keys import hash_key, make_display
    with SessionLocal() as s:
        lic = s.query(License).first()
        assert lic.key_hash == hash_key(plaintext)
        assert lic.key_display == make_display(plaintext)


# ---------- /v1/check looks up by hash --------------------------------------


def test_v1_check_succeeds_even_when_plaintext_column_is_wrong(make_client, monkeypatch):
    """Tamper the plaintext `key` column on a license to a different value
    but leave `key_hash` correct. /v1/check with the original plaintext
    must still succeed — proving the lookup is via key_hash, not key."""
    from cryptography.fernet import Fernet
    c = make_client(
        LICENSE_KEY_PEPPER="testpepper" * 4,
        LICENSE_KEY_ENCRYPTION_KEY=Fernet.generate_key().decode(),
    )
    r = c.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    r = c.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={"email": "alice@example.com", "plan": "standard", "valid_days": 30},
    )
    plaintext = r.json()["key"]

    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        lic = s.query(License).first()
        lic.key = "tampered_garbage_value"
        s.commit()

    r = c.post(
        "/v1/check",
        json={"key": plaintext, "install_id": "ii-1", "version": "1.0"},
    )
    assert r.status_code == 200, "lookup should succeed via key_hash, not key"
