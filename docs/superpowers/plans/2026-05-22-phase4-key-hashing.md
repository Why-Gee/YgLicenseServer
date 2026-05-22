# Phase 4 — At-Rest Key Hashing + JWT `aud` (v1.0.0, breaking) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace plaintext storage of license keys with a server-peppered BLAKE2b hash + a non-sensitive display fragment; add JWT `aud` claim; ship as v1.0.0 with documented breaking changes.

**Architecture:** Add `licenses.key_hash` (BLAKE2b-256 hex, keyed with a server-side pepper from env) + `licenses.key_display` (truncated prefix + tail for safe UI rendering). Migration backfills both columns from the existing plaintext `key` column, applies UNIQUE NOT NULL constraints, then keeps the plaintext column in place for one release (drop in v1.1). `/v1/check` switches from `filter_by(key=...)` to `filter_by(key_hash=hash(...))`. All UI / CSV / JSON surfaces switch from `r.key` to `r.key_display`. Plaintext is only ever surfaced at the moment of issuance: the API response, the email, and the post-redirect admin-UI flash. JWT `aud` claim is added with explicit breaking-change documentation.

**Tech Stack:** No new deps (Python's `hashlib.blake2b` ships with stdlib). New env var `LICENSE_KEY_PEPPER` (32-byte base64 or hex). Alembic for the migration.

**Spec:** `docs/superpowers/specs/2026-05-22-security-hardening-design.md` (Phase 4 section).

**Branch:** `yg/Vulnerabilities-21-5-2026` (continued from Phase 3).

**Breaking changes (documented in CHANGELOG):**
1. License-key plaintext no longer visible in admin UI listings; admin sees the truncated `key_display`. Plaintext is shown ONCE at issuance.
2. JWT `aud` claim added — clients must pass `audience=<product_slug>` to `jwt.decode` or `options={"verify_aud": False}`.
3. `LICENSE_KEY_PEPPER` env var required when `LICENSE_SERVER_REQUIRE_KEK=1`. Soft-warning otherwise.

---

## File Structure

**Created:**
- `app/license_keys.py` — pure hashing/display helpers (`hash_key`, `make_display`).
- `alembic/versions/<rev>_license_key_hash.py` — schema + backfill.
- `tests/test_phase4_hashing.py` — TDD tests for hashing helpers + integration paths.

**Modified:**
- `app/config.py` — `license_key_pepper` setting + env reader.
- `app/main.py::_validate_secrets_at_boot` — hard exit when REQUIRE_KEK=1 + pepper unset.
- `app/models.py::License` — `key_hash` + `key_display` columns.
- `app/services/licenses.py::issue_license` — compute hash + display on insert; return plaintext via IssueResult.
- `app/services/check.py::check_license` — lookup by hash.
- `app/stripe_webhook.py` — Stripe `invoice.paid` path computes hash + display.
- `app/routers/api.py::admin_list_licenses` — response uses `key_display`.
- `app/routers/exports.py::export_licenses` — CSV uses `key_display`.
- `app/templates/product_detail.html` — license table column uses `key_display`; issuance modal still surfaces plaintext from the response.
- `app/static/admin.js` — issuance flow shows plaintext once, then strips the URL param.
- `app/signing.py::sign_license_jwt` — add `"aud": product.slug`.
- `tests/test_check.py` and any other test that calls `jwt.decode` — pass `audience=product_slug`.
- `README.md` — client integration example notes new claim + storage shape.
- `.env.example` — document `LICENSE_KEY_PEPPER`.
- `pyproject.toml`, `app/__init__.py` — bump to 1.0.0.

---

## Task 1: pepper config + hashing helpers

**Files:**
- Create: `app/license_keys.py`
- Modify: `app/config.py`
- Modify: `app/main.py::_validate_secrets_at_boot`
- Create: `tests/test_phase4_hashing.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_phase4_hashing.py`:

```python
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
```

- [ ] **Step 2: Run — verify failure**

```bash
pytest tests/test_phase4_hashing.py -v
```

Expected: all 7 tests FAIL (config field absent, helper module absent, boot validator gate absent).

- [ ] **Step 3: Add `license_key_pepper` to `Settings`**

In `app/config.py`, add to `Settings`:

```python
    # BLAKE2b key (pepper) used by app.license_keys.hash_key. Required when
    # LICENSE_SERVER_REQUIRE_KEK=1 so a DB dump without the pepper cannot
    # brute-force keys. Unset means hash_key() raises — there is no plaintext
    # fallback for license lookup in v1.0+.
    license_key_pepper: str = ""
```

In `get_settings()` factory, add the reader:

```python
        license_key_pepper=os.environ.get("LICENSE_KEY_PEPPER", ""),
```

- [ ] **Step 4: Create `app/license_keys.py`**

```python
"""License-key hashing + display helpers (v1.0+).

Two columns on `licenses` cooperate:
- `key_hash`    — BLAKE2b-256 hex of the plaintext, keyed with a server
                  pepper. Used by /v1/check lookups. Without the pepper a
                  DB dump cannot brute-force keys to plaintext.
- `key_display` — Truncated form `<prefix>_<first6>…<last4>` safe to show
                  anywhere in the UI. Recognisable but non-recoverable.

The plaintext key is shown to the admin EXACTLY ONCE: the issuance HTTP
response. After that the only record on disk is the hash + display.

Why BLAKE2b: faster than SHA-256 and the natively-keyed mode means we
don't have to do HMAC-SHA256 ourselves. Hex (not base64) so the value
is index-friendly across SQLite + Postgres without encoding tricks.
"""
from __future__ import annotations

import hashlib

from app.config import get_settings


def hash_key(plaintext: str) -> str:
    """Pepper-keyed BLAKE2b-256 of `plaintext`. Returns 64 hex chars.

    Raises RuntimeError if LICENSE_KEY_PEPPER is unset — we never want to
    silently store unpeppered hashes that would mismatch the configured-
    pepper hashes once an admin sets one.
    """
    pepper = get_settings().license_key_pepper
    if not pepper:
        raise RuntimeError(
            "LICENSE_KEY_PEPPER is unset. Set a 32-byte secret in env "
            "(e.g. `python -c 'import secrets; print(secrets.token_hex(32))'`) "
            "before issuing or validating licenses."
        )
    h = hashlib.blake2b(plaintext.encode("utf-8"), digest_size=32, key=pepper.encode("utf-8"))
    return h.hexdigest()


def make_display(plaintext: str) -> str:
    """Build the safe-to-show truncated form. `<prefix>_<first6>…<last4>`
    if the key matches the `<prefix>_<body>` shape; otherwise just
    `<first6>…<last4>`. Total length capped at 32 chars."""
    if "_" in plaintext:
        prefix, _, body = plaintext.partition("_")
        head = body[:6]
        tail = body[-4:] if len(body) >= 10 else body
        return f"{prefix}_{head}…{tail}"
    head = plaintext[:6]
    tail = plaintext[-4:] if len(plaintext) >= 10 else plaintext
    return f"{head}…{tail}"
```

- [ ] **Step 5: Wire pepper requirement into boot validator**

In `app/main.py::_validate_secrets_at_boot`, after the KEK-required branch added in Phase 2, add:

```python
    if s.require_kek and not s.license_key_pepper:
        log.critical(
            "LICENSE_SERVER_REQUIRE_KEK=1 set but LICENSE_KEY_PEPPER is "
            "unset. Refusing to boot — without a pepper, key_hash lookups "
            "are unkeyed and a DB dump trivially recovers all license "
            "keys. Generate one with `python -c 'import secrets; "
            "print(secrets.token_hex(32))'` and set it in the env."
        )
        sys.exit(78)
```

Also add a soft warning when REQUIRE_KEK is False but pepper is unset:

```python
    if not s.license_key_pepper and not s.require_kek:
        log.warning(
            "LICENSE_KEY_PEPPER is unset; /v1/check and license issuance "
            "will raise RuntimeError until you configure one. Generate a "
            "pepper with `python -c 'import secrets; print(secrets.token_hex(32))'`."
        )
```

- [ ] **Step 6: Run the new tests + full suite**

```bash
pytest tests/test_phase4_hashing.py -v
pytest -q
```

All green.

- [ ] **Step 7: Commit**

```bash
git add app/config.py app/license_keys.py app/main.py tests/test_phase4_hashing.py
git commit -m "$(cat <<'EOF'
H8 (1/8): pepper config + hash_key/make_display helpers

New env var LICENSE_KEY_PEPPER + Settings field. New module
app/license_keys.py with hash_key (peppered BLAKE2b-256) and
make_display (truncated prefix+tail). Boot validator hard-exits when
REQUIRE_KEK=1 + pepper unset; soft-warns when pepper unset alone.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: schema + migration with backfill

**Files:**
- Modify: `app/models.py::License`
- Create: `alembic/versions/<rev>_license_key_hash.py`
- Test: `tests/test_phase4_hashing.py` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_phase4_hashing.py`:

```python
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
```

- [ ] **Step 2: Run — verify failure**

```bash
pytest tests/test_phase4_hashing.py -v -k "schema or migration_backfills"
```

Both must FAIL (columns absent).

- [ ] **Step 3: Add columns to `app/models.py::License`**

After the existing `webhook_url_source` + `allow_http_webhook` columns:

```python
    # v1.0+: BLAKE2b-keyed hash of the plaintext key. /v1/check looks up
    # licenses by this column, not by the plaintext. The plaintext column
    # is retained for one release (deprecated) so an in-place migration
    # rollback is possible; drop in v1.1.
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    # Truncated prefix+tail safe to show anywhere. `<prefix>_<first6>…<last4>`.
    key_display: Mapped[str] = mapped_column(String(32), nullable=False)
```

Note: both are NOT NULL. The migration backfills before applying the constraint.

- [ ] **Step 4: Write the Alembic migration**

```bash
alembic revision -m "license key hash"
```

Edit:

```python
"""license key hash columns

Revision ID: <keep generated>
Revises: 82b53e74e9ac
Create Date: <keep generated>

v1.0 breaking change. Adds licenses.key_hash + key_display columns.
Both nullable at first; populated by the data backfill loop below
using the configured LICENSE_KEY_PEPPER; then constraints applied.

Requires LICENSE_KEY_PEPPER in the env at upgrade time. If unset and
the table has rows, the migration aborts so the operator can't
silently set the pepper to a different value later (which would make
every backfilled hash mismatch the live lookups).
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "<keep generated>"
down_revision: str | Sequence[str] | None = "82b53e74e9ac"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Skip the data-rewrap loop in --sql / offline mode for the same reason
    # the 8a336b18bca1 migration does: non-deterministic ops can't be emitted
    # as static SQL.
    if op.get_context().as_sql:
        print(
            "-- NOTE: license-key hash backfill skipped in --sql/offline mode. "
            "Run `alembic upgrade head` online against the same DB after "
            "applying this DDL with LICENSE_KEY_PEPPER set."
        )
        with op.batch_alter_table("licenses") as batch:
            batch.add_column(sa.Column("key_hash", sa.String(64), nullable=True))
            batch.add_column(sa.Column("key_display", sa.String(32), nullable=True))
        return

    # Phase 1: add columns nullable so the backfill can populate.
    with op.batch_alter_table("licenses") as batch:
        batch.add_column(sa.Column("key_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("key_display", sa.String(32), nullable=True))

    # Phase 2: pepper check + backfill.
    from app.config import get_settings
    from app.license_keys import hash_key, make_display

    s = get_settings()
    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id, key FROM licenses WHERE key_hash IS NULL")).fetchall()

    if rows and not s.license_key_pepper:
        raise RuntimeError(
            "license-key hash migration: rows present but LICENSE_KEY_PEPPER "
            "is unset. Set the pepper before running this migration; the "
            "value MUST then be stable for the lifetime of the deployment."
        )

    for row in rows:
        plaintext = row[1]
        conn.execute(
            sa.text(
                "UPDATE licenses SET key_hash = :h, key_display = :d "
                "WHERE id = :pid"
            ),
            {"h": hash_key(plaintext), "d": make_display(plaintext), "pid": row[0]},
        )

    # Phase 3: tighten to NOT NULL + UNIQUE on key_hash.
    with op.batch_alter_table("licenses") as batch:
        batch.alter_column("key_hash", existing_type=sa.String(64), nullable=False)
        batch.alter_column("key_display", existing_type=sa.String(32), nullable=False)
        batch.create_unique_constraint("uq_licenses_key_hash", ["key_hash"])
        batch.create_index("ix_licenses_key_hash", ["key_hash"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("licenses") as batch:
        batch.drop_index("ix_licenses_key_hash")
        batch.drop_constraint("uq_licenses_key_hash", type_="unique")
        batch.drop_column("key_display")
        batch.drop_column("key_hash")
```

- [ ] **Step 5: Run tests + full suite**

```bash
pytest tests/test_phase4_hashing.py -v -k "schema or migration_backfills"
pytest -q
```

If pre-existing tests in `tests/test_check.py` etc fail because they issue licenses and the issuance code path doesn't yet write the new columns, that's expected for THIS task (Task 3 will fix issuance). For now, the test_phase4 tests should be green and `test_migrations.py` if it exercises the new migration should pass.

If the existing suite breaks because of the new NOT NULL column, the broken tests will be fixed in Task 3. Run only the test_phase4 tests for now:

```bash
pytest tests/test_phase4_hashing.py -v
```

- [ ] **Step 6: Commit**

```bash
git add app/models.py alembic/versions/*_license_key_hash.py tests/test_phase4_hashing.py
git commit -m "$(cat <<'EOF'
H8 (2/8): licenses.key_hash + key_display schema + migration

Two new columns + migration that backfills both from the existing
plaintext column using the configured LICENSE_KEY_PEPPER. Plaintext
column retained for one release (drop in v1.1). Migration refuses
to run if rows are present without a pepper configured.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: issuance writes hash + display

**Files:**
- Modify: `app/services/licenses.py::issue_license`
- Modify: `app/stripe_webhook.py::_extend_or_create` (Stripe `invoice.paid` path)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_phase4_hashing.py`:

```python
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
```

- [ ] **Step 2: Run — verify failure**

```bash
pytest tests/test_phase4_hashing.py::test_admin_issue_populates_hash_and_display -v
```

FAIL (issuance doesn't write the new columns).

- [ ] **Step 3: Update `app/services/licenses.py::issue_license`**

At the top of the file add:

```python
from app.license_keys import hash_key, make_display
```

Then in the function body, replace the key generation block:

```python
    key = f"{product.key_prefix}_" + secrets.token_urlsafe(32)
    lic = License(
        product_id=product.id,
        customer_id=cust.id,
        key=key,
        # ...
    )
```

With:

```python
    key = f"{product.key_prefix}_" + secrets.token_urlsafe(32)
    lic = License(
        product_id=product.id,
        customer_id=cust.id,
        key=key,                           # deprecated; will drop in v1.1
        key_hash=hash_key(key),
        key_display=make_display(key),
        # ... rest of existing fields ...
    )
```

- [ ] **Step 4: Update `app/stripe_webhook.py::_extend_or_create`**

Same import + same change to the License constructor call there:

```python
        key = f"{product.key_prefix}_" + secrets.token_urlsafe(32)
        lic = License(
            product_id=product.id,
            customer_id=cust.id,
            key=key,
            key_hash=hash_key(key),
            key_display=make_display(key),
            # ... rest ...
        )
```

- [ ] **Step 5: Run tests + full suite**

```bash
pytest tests/test_phase4_hashing.py -v
pytest -q
```

`test_admin_issue_populates_hash_and_display` green. Note: existing tests that issue licenses now succeed (the issuance writes all required columns) but tests that call `/v1/check` with the plaintext key will still fail because /v1/check is still looking up by `key`, not `key_hash`. Task 4 fixes that.

- [ ] **Step 6: Commit**

```bash
git add app/services/licenses.py app/stripe_webhook.py tests/test_phase4_hashing.py
git commit -m "$(cat <<'EOF'
H8 (3/8): issuance writes key_hash + key_display alongside plaintext

Both admin-UI path (issue_license) and Stripe invoice.paid path
(_extend_or_create) now compute the BLAKE2b hash + truncated display
at insert time. Plaintext column still written for one-release
backward compat; will be dropped in v1.1.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `/v1/check` looks up by hash

**Files:**
- Modify: `app/services/check.py::check_license`
- Test: `tests/test_phase4_hashing.py` (append)

- [ ] **Step 1: Write the failing test**

Append:

```python
# ---------- /v1/check looks up by hash --------------------------------------


def test_v1_check_uses_hash_lookup(make_client, monkeypatch):
    """A client posting the plaintext key MUST resolve to the license via
    hash lookup. This works the same as today from the client's point of
    view, but the server-side lookup column changes."""
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
    plaintext = r.json()["key"]
    # /v1/check happy path:
    r = c.post(
        "/v1/check",
        json={"key": plaintext, "install_id": "ii-1", "version": "1.0"},
    )
    assert r.status_code == 200, r.text
    # Lookup miss (wrong key) → invalid_key.
    r = c.post(
        "/v1/check",
        json={"key": "asm_NOT_A_REAL_KEY", "install_id": "ii-1", "version": "1.0"},
    )
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "invalid_key"
```

- [ ] **Step 2: Run — verify failure**

```bash
pytest tests/test_phase4_hashing.py::test_v1_check_uses_hash_lookup -v
```

Should still PASS because plaintext is still stored — `filter_by(key=plaintext)` still works. Task 4 is about changing the LOOKUP COLUMN, which is a code refactor that doesn't change end-to-end behaviour today. So this test isn't a red-green test in the classical sense; it's a *post-condition* test that should remain green AFTER the lookup-column change.

Add a stronger test that verifies the lookup is via hash, not plaintext:

```python
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
```

This test will FAIL until Task 4's lookup change lands.

- [ ] **Step 3: Run the new test — verify it fails**

```bash
pytest tests/test_phase4_hashing.py::test_v1_check_succeeds_even_when_plaintext_column_is_wrong -v
```

FAIL (current code filters by `key=`).

- [ ] **Step 4: Switch the lookup in `app/services/check.py`**

Change:

```python
    lic = db.query(License).filter_by(key=key).one_or_none()
```

To:

```python
    from app.license_keys import hash_key
    lic = db.query(License).filter_by(key_hash=hash_key(key)).one_or_none()
```

(Or hoist the import to module level — either is fine.)

- [ ] **Step 5: Run tests + full suite**

```bash
pytest tests/test_phase4_hashing.py -v
pytest -q
```

Suite should remain green; the lookup is now via hash, but all existing test paths submit the correct plaintext key from the issuance response, so behaviour is preserved.

- [ ] **Step 6: Commit**

```bash
git add app/services/check.py tests/test_phase4_hashing.py
git commit -m "$(cat <<'EOF'
H8 (4/8): /v1/check looks up license by key_hash

Switch from filter_by(key=plaintext) to filter_by(key_hash=hash_key(plaintext)).
Plaintext is no longer required to be stored correctly; the hash is the
authoritative lookup column. Behaviour is end-to-end identical from the
client's perspective.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: display layer (UI + CSV + JSON show key_display)

**Files:**
- Modify: `app/routers/api.py::admin_list_licenses` — replace `r.key` with `r.key_display` in response.
- Modify: `app/routers/exports.py::export_licenses` — CSV "key" column uses `key_display`.
- Modify: `app/templates/product_detail.html` — license table cell + per-license JSON payload use `key_display`.
- Modify: `app/static/admin.js` — issuance modal flash still shows plaintext (from the URL flash param), but the listing always shows display.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_phase4_hashing.py`:

```python
# ---------- display layer ---------------------------------------------------


def test_admin_list_licenses_returns_key_display_not_plaintext(make_client, monkeypatch):
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
    r = c.get(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
    )
    assert r.status_code == 200
    item = r.json()["items"][0]
    # New v1.0 semantics: 'key' field in admin list shows truncated display.
    assert item["key"] != plaintext, "plaintext leaked into admin list response"
    assert "…" in item["key"], f"key field is not truncated: {item['key']}"
    assert item["key"].startswith("asm_")


def test_csv_export_uses_key_display(make_client, monkeypatch):
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
    r = c.get(
        "/v1/admin/exports/products/asm/licenses.csv",
        headers={"Authorization": "Bearer test-admin"},
    )
    assert r.status_code == 200
    body = r.text
    assert plaintext not in body, "plaintext leaked into CSV export"
    assert "…" in body, "key_display not present in CSV export"
```

- [ ] **Step 2: Run — verify failure**

```bash
pytest tests/test_phase4_hashing.py -v -k "list_licenses_returns or csv_export_uses"
```

Both FAIL — current code emits plaintext `r.key`.

- [ ] **Step 3: Switch `admin_list_licenses` to `key_display`**

In `app/routers/api.py::admin_list_licenses`, change the dict comprehension:

```python
        "items": [
            {
                "id": r.id, "key": r.key_display, "plan": r.plan, "status": r.status,
                # ... rest unchanged ...
            }
            for r in page.items
        ],
```

(Keep the response field name `"key"` so clients don't break the response-shape contract beyond the value semantic; the value changes from plaintext to display.)

- [ ] **Step 4: Switch the CSV export to `key_display`**

In `app/routers/exports.py::export_licenses`, change the row generator:

```python
    def gen() -> Iterator[list[str]]:
        for r in rows_q:
            yield [
                r.id, r.key_display, r.plan, r.status, str(r.max_users),
                _iso(r.valid_until),
                r.customer.email if r.customer else "",
                r.customer.name if (r.customer and r.customer.name) else "",
                r.webhook_url or "",
                _iso(r.created_at),
            ]
```

(Column header stays `"key"`; value flips.)

- [ ] **Step 5: Switch the admin UI template**

In `app/templates/product_detail.html`, find the license table row and change `<code>{{ lic.key }}</code>` to `<code>{{ lic.key_display }}</code>` in the license listing.

In the per-license JSON payload at the top of the template (search for `"key": {{ lic.key|tojson }}`), change to:

```html
      "key_display": {{ lic.key_display|tojson }},
```

(Drop the `"key": ...` line entirely from the JSON payload — the modal's edit flow no longer needs plaintext.)

In the modal's JS edit branch, change:

```javascript
      keyEl.textContent = lic.key;
```

To:

```javascript
      keyEl.textContent = lic.key_display;
```

- [ ] **Step 6: Handle the issuance flash**

The issuance redirect goes to `/admin/products/{slug}?issued={license_id}`. The admin needs to see the plaintext key ONCE. The cleanest path: the form-issuance handler in `app/routers/admin_ui/licenses.py::license_issue` already redirects with `?issued={license_id}`. Change it to pass the plaintext key as a separate query param that the template can flash:

In `app/routers/admin_ui/licenses.py::license_issue`, change the success redirect:

```python
    return RedirectResponse(
        f"/admin/products/{slug}?issued={result.license.id}&key={result.license.key}",
        status_code=303,
    )
```

(The plaintext is URL-encoded by RedirectResponse; safe to embed in the query string for the one-shot display.)

In `app/templates/product_detail.html`, replace the existing "issued" flash block:

```html
{% if request.query_params.get('issued') %}
<div class="success">license issued. find the key in the table below — copy it now (we don't show it again in plain text). if a webhook URL was set, the signing secret is shown in the edit modal and is also only displayed once.</div>
{% endif %}
```

With:

```html
{% if request.query_params.get('issued') and request.query_params.get('key') %}
<div class="success" style="word-break:break-all;">
  <p>license issued. <strong>copy this key now — it is not shown again:</strong></p>
  <pre style="margin:.5em 0;background:rgba(0,0,0,.2);padding:.5em;border-radius:4px;">{{ request.query_params.get('key') }}</pre>
  <p>after this page reload, the listing shows only a truncated <code>{{ '<prefix>_<first6>…<last4>' }}</code> form. if a webhook URL was set, the signing secret is shown in the edit modal and is also only displayed once.</p>
</div>
{% endif %}
```

In `app/static/admin.js`, add `'key'` to the `FLASH_PARAMS` list that gets stripped on page-render:

```javascript
  var FLASH_PARAMS = [
    'error',
    'product_edited',
    'edited',
    'issued',
    'key',
    'webhook_lid',
    // ...
  ];
```

- [ ] **Step 7: Run tests + full suite**

```bash
pytest tests/test_phase4_hashing.py -v -k "list_licenses or csv_export"
pytest -q
```

All green. If `tests/test_exports.py` has assertions on the plaintext key being in CSV output, update them to check for `key_display` (truncated `…` form).

- [ ] **Step 8: Commit**

```bash
git add app/routers/api.py app/routers/exports.py app/templates/product_detail.html app/routers/admin_ui/licenses.py app/static/admin.js tests/test_phase4_hashing.py tests/test_exports.py
git commit -m "$(cat <<'EOF'
H8 (5/8): admin UI + CSV + JSON show key_display instead of plaintext

The 'key' field in admin_list_licenses + the license-CSV column +
the per-product license table all show <prefix>_<first6>…<last4>.
Plaintext is surfaced exactly once: in the post-issuance redirect's
query string, rendered in a one-shot 'copy now' flash banner.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: JWT `aud` claim + update existing tests

**Files:**
- Modify: `app/signing.py::sign_license_jwt`
- Modify: `tests/test_check.py` (existing tests that call `jwt.decode`)
- Modify: `tests/test_phase2_authn.py::test_jwt_carries_kid_claim` (the anti-regression must now flip)
- Test: `tests/test_phase4_hashing.py` (new test asserts `aud` present)

- [ ] **Step 1: Write the failing test**

Append:

```python
# ---------- JWT aud claim ---------------------------------------------------


def test_jwt_carries_aud_claim(make_client, monkeypatch):
    """v1.0+: JWT payload includes aud = product.slug. Clients MUST pass
    audience= to jwt.decode or set verify_aud=False."""
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
    r = c.post(
        "/v1/check",
        json={"key": plaintext, "install_id": "ii-1", "version": "1.0"},
    )
    assert r.status_code == 200
    token = r.json()["jwt"]
    import jwt as pyjwt
    claims = pyjwt.decode(token, options={"verify_signature": False})
    assert claims.get("aud") == "asm", claims
```

- [ ] **Step 2: Update the anti-regression in `tests/test_phase2_authn.py`**

Find `test_jwt_carries_kid_claim` (added in Phase 2). It currently asserts `"aud" not in claims`. That assertion is now obsolete — flip it.

Replace:

```python
    # Explicit anti-regression: aud must NOT be added today (breaking change).
    assert "aud" not in claims, (
        f"aud present in v0.22 token; defer to v1.0 with breaking changes: {claims}"
    )
```

With:

```python
    # v1.0+: aud IS present (was deferred in v0.22). Clients must pass
    # audience= to jwt.decode or disable aud verification.
    assert claims.get("aud"), f"aud missing in v1.0 token: {claims}"
```

- [ ] **Step 3: Run — verify failure**

```bash
pytest tests/test_phase4_hashing.py::test_jwt_carries_aud_claim tests/test_phase2_authn.py::test_jwt_carries_kid_claim -v
```

Both FAIL.

- [ ] **Step 4: Add the claim in `app/signing.py`**

Find the `payload = {...}` dict and add `"aud": product.slug`. Updated payload:

```python
    payload = {
        "iss": product.jwt_issuer,
        "kid": product.id,
        "aud": product.slug,         # v1.0+: clients MUST pass audience= or verify_aud=False
        "iat": int(now.timestamp()),
        "exp": int(cap.timestamp()),
        "product": product.slug,
        "license_id": license_id,
        "install_id": install_id,
        "plan": plan,
        "max_users": max_users,
        "features": features,
        "valid_until": int(vu.timestamp()),
    }
```

Update the comment block above the dict to reflect the new claim's presence.

- [ ] **Step 5: Fix existing `jwt.decode` test callers**

`tests/test_check.py` has at least two calls to `jwt_lib.decode(token, pub, algorithms=["EdDSA"], options={"verify_exp": False})`. With `aud` now in the token, pyjwt raises `InvalidAudienceError`. Update each to pass `audience="asm"` (or the product slug being tested):

Find every `jwt_lib.decode(...)` call in `tests/test_check.py` and add `audience=<slug>` (or `options={"verify_exp": False, "verify_aud": False}` if you want to skip aud checking entirely — pick consistently).

Recommended: pass `audience="asm"` explicitly. If the test issues against a different slug, match it.

For `test_two_products_isolated` specifically, the `decode` call is checked TWICE under different pubkeys; update both.

- [ ] **Step 6: Run tests + full suite**

```bash
pytest tests/test_phase4_hashing.py tests/test_phase2_authn.py tests/test_check.py -v
pytest -q
```

All green.

- [ ] **Step 7: Commit**

```bash
git add app/signing.py tests/test_phase4_hashing.py tests/test_phase2_authn.py tests/test_check.py
git commit -m "$(cat <<'EOF'
H8 (6/8): add JWT aud claim (v1.0 breaking)

aud = product.slug. Was deferred from v0.22 because pyjwt validates
aud whenever present — clients decoding without passing audience= now
raise InvalidAudienceError. Documented in README; existing test
callers updated to pass audience= explicitly.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: README + CHANGELOG breaking-change docs

**Files:**
- Modify: `README.md` — client integration example shows new shape.
- Create: `CHANGELOG.md` (if absent; or append).
- Modify: `.env.example`, `.env.prod.example` — document `LICENSE_KEY_PEPPER`.

- [ ] **Step 1: Update README's client-integration example**

In `README.md`, find the existing `jwt.decode(...)` example block. The current text (after Phase 2 update) is:

```python
import jwt
# v0.22+: tokens carry a `kid` claim (opaque product id); harmless to ignore.
# v1.0+ (planned): tokens will also carry `aud` = product slug. Once that lands,
# this call MUST pass `audience=product_slug` or pyjwt will raise InvalidAudienceError.
# Today (no aud), the call below works as-is.
claims = jwt.decode(token, public_key_pem, algorithms=["EdDSA"], options={"verify_exp": False})
# claims has: license_id, install_id, plan, max_users, features, valid_until, product, kid
```

Replace with:

```python
import jwt
# v1.0+: tokens carry kid (opaque product id) + aud (product slug).
# audience= is REQUIRED — pyjwt will raise InvalidAudienceError otherwise.
claims = jwt.decode(
    token, public_key_pem,
    algorithms=["EdDSA"],
    audience=product_slug,
    options={"verify_exp": False},
)
# claims has: license_id, install_id, plan, max_users, features, valid_until, product, kid, aud
```

Add a "Storage shape" note in the README's `Concepts > License` paragraph:

> **License** — a key (`asm_…`) bound to one customer + one product. Stored on the server as a peppered BLAKE2b hash plus a truncated display form; the plaintext is shown ONCE at issuance and not recoverable from the DB. Customers must save the key when it's issued.

- [ ] **Step 2: Append CHANGELOG.md (create if missing)**

Add a top section for v1.0.0:

```markdown
# Changelog

## v1.0.0 — breaking

### License-key storage

The plaintext license key is no longer stored in the admin UI listings, CSV
exports, or admin JSON API response. The server stores a BLAKE2b-keyed hash
(for /v1/check lookups) and a truncated display form (`<prefix>_<first6>…<last4>`)
for safe rendering. **Plaintext is shown exactly once at issuance** — in the
issuance HTTP response, the customer-email body, and the post-redirect admin-UI
flash banner. Save it then; you can't recover it from a DB dump.

The deprecated plaintext `key` column on the `licenses` table is retained for
this release as a safety net for in-place rollbacks. It will be dropped in v1.1.

### LICENSE_KEY_PEPPER env var

Set a 32-byte secret in `LICENSE_KEY_PEPPER`:

```
python -c 'import secrets; print(secrets.token_hex(32))'
```

This is the pepper for the at-rest hashing. **It must remain stable for the
lifetime of the deployment** — rotating it requires re-issuing every license.
Required when `LICENSE_SERVER_REQUIRE_KEK=1`; soft-warned otherwise.

### JWT aud claim

JWT payload now includes `aud = product.slug`. Client code that decodes via
`jwt.decode(token, pub, algorithms=[...], options={"verify_exp": False})` will
raise `InvalidAudienceError` until the call adds `audience=product_slug`. See
the README's client-integration example.

### Upgrade procedure

1. Generate a pepper and add `LICENSE_KEY_PEPPER=<hex>` to your env file.
2. (Optional but recommended) set `LICENSE_SERVER_REQUIRE_KEK=1` so the
   server hard-exits if either of KEK or pepper is missing.
3. Take a DB backup before upgrading. The migration backfills `key_hash` +
   `key_display` from the existing plaintext, then applies UNIQUE NOT NULL.
4. `./deploy.ps1` (or your equivalent) to ship the new image.
5. Update every client that decodes JWTs to pass `audience=product_slug`.
```

- [ ] **Step 3: Update `.env.example` and `.env.prod.example`**

Append to each:

```
# 32-byte hex secret — pepper for the BLAKE2b key hash. Must be stable
# for the lifetime of the deployment; rotating it requires re-issuing
# every license. Generate with:
#   python -c 'import secrets; print(secrets.token_hex(32))'
LICENSE_KEY_PEPPER=
```

- [ ] **Step 4: Commit**

```bash
git add README.md CHANGELOG.md .env.example .env.prod.example
git commit -m "$(cat <<'EOF'
H8 (7/8): docs for v1.0 breaking changes

README client-integration example updated to pass audience= to
jwt.decode and to mention the new license-key storage shape.
CHANGELOG.md introduces v1.0.0 with the upgrade procedure.
.env.example + .env.prod.example document LICENSE_KEY_PEPPER.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Bump to v1.0.0

**Files:**
- Modify: `app/__init__.py` → `"1.0.0"`
- Modify: `pyproject.toml` → `version = "1.0.0"`

- [ ] **Step 1: Bump**

```python
__version__ = "1.0.0"
```

```toml
version = "1.0.0"
```

- [ ] **Step 2: Full suite green**

```bash
pytest -q
```

- [ ] **Step 3: Commit**

```bash
git add app/__init__.py pyproject.toml
git commit -m "$(cat <<'EOF'
chore: bump to v1.0.0 (breaking)

Phase 4 at-rest license-key hashing + JWT aud claim. See CHANGELOG.md
for the breaking-change list and upgrade procedure.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## End-of-phase check

- [ ] `pytest -q` green.
- [ ] `alembic upgrade head` on a fresh sqlite with `LICENSE_KEY_PEPPER` set — all migrations apply cleanly.
- [ ] `alembic upgrade head` on a fresh sqlite WITHOUT `LICENSE_KEY_PEPPER` — must succeed when no rows exist (or fail loud if rows present).
- [ ] Boot the server with `LICENSE_SERVER_REQUIRE_KEK=1` + missing pepper — must exit 78.
- [ ] Issue a license via the admin UI — verify the plaintext appears in the post-redirect flash banner and is then stripped from the URL.
- [ ] List licenses — table shows `key_display`, not plaintext.
- [ ] Download a licenses CSV — plaintext absent, key_display present.
- [ ] Verify a client decoding the JWT with `audience=product_slug` succeeds; without `audience=` fails (the breaking change is real).

After Phase 4, the v1.0 line is shipped. v1.1 will drop the deprecated plaintext `key` column once an operational soak period has passed.
