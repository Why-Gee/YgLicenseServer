# Phase 2 — Authn + Crypto Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add KEK-required gate, drop spoofable XFF parsing, add JWT `kid`+`aud` claims, and add TOTP-based MFA on admin login; ship as v0.22.0.

**Architecture:** Four independent hardening items + one MFA feature. KEK gate and XFF are tiny config/code shifts. JWT claim additions are forward-compatible (clients ignore unknown claims). MFA is a new table + 6 routes + 2 templates + login-flow split, all behind opt-in `enabled` flag so default deployments keep working unchanged.

**Tech Stack:** Adds `pyotp>=2.9` and `qrcode>=7.4` deps. Fernet encryption for TOTP secret at rest (existing `app.keystore` envelope). SHA-256 for single-use recovery code digests.

**Spec:** `docs/superpowers/specs/2026-05-22-security-hardening-design.md` (Phase 2 section).

**Branch:** `yg/Vulnerabilities-21-5-2026` (continued from Phase 1).

---

## File Structure

**Created:**
- `app/routers/admin_ui/mfa.py` — TOTP enrol / verify-enrol / disable / regen-recovery + login-mfa-step endpoints.
- `app/templates/mfa.html` — admin settings page for MFA (enrol QR or disable + regen).
- `app/templates/login_mfa.html` — code-entry form after first-factor token success.
- `app/services/mfa.py` — pure logic: generate secret, build provisioning URI, verify code, hash + check recovery codes.
- `alembic/versions/<rev>_admin_mfa.py` — `admin_mfa` table.
- `tests/test_phase2_authn.py` — TDD tests for H1, H2, H3.
- `tests/test_mfa.py` — full TOTP flow tests.

**Modified:**
- `app/routers/api.py:69-90` (`_client_ip_hash`), `app/rate_limit.py:32-45` (`client_ip`) — drop XFF parsing, return `request.client.host` directly (H1).
- `app/signing.py::sign_license_jwt` — add `kid` + `aud` claims (H2).
- `app/config.py`, `app/main.py` — `LICENSE_SERVER_REQUIRE_KEK` env-var + boot gate (H3).
- `app/keystore.py::encrypt_secret` — refuse plaintext fallthrough when KEK required (H3).
- `app/models.py` — `AdminMfa` model (H7).
- `app/routers/admin_ui/__init__.py` — register `mfa` router (H7).
- `app/routers/admin_ui/auth.py::login` — split into first-factor + MFA-step (H7).
- `app/templates/base.html` — add "MFA" sidebar entry (H7).
- `pyproject.toml` — add `pyotp` + `qrcode`; bump version (T6).
- `app/__init__.py` — bump version (T6).

---

## Task 1: H1 — drop XFF parsing

**Files:**
- Modify: `app/routers/api.py:69-90`
- Modify: `app/rate_limit.py:32-45`
- Test: `tests/test_phase2_authn.py` (new)

In our documented deploy Caddy is the immediate peer on loopback, so `request.client.host` is already the correct last-hop IP. Reading any client-supplied header is strictly worse — Caddy *appends* XFF, so the leftmost entry is attacker-controlled.

- [ ] **Step 1: Write the failing test**

Create `tests/test_phase2_authn.py`:

```python
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


def test_xff_header_does_not_affect_install_ip_hash(client):
    """Sending X-Forwarded-For must NOT change the recorded ip_addr_hash.
    Caddy is the immediate peer in prod (loopback), so the only safe source
    is request.client.host. Trusting the leftmost XFF entry is strictly
    worse — Caddy APPENDS XFF, so the leftmost is whatever the client sent."""
    _create_product(client)
    key = _issue(client)

    # Two calls, different XFF, same peer (TestClient => 'testclient').
    # If XFF was honoured, ip_addr_hash would change between calls.
    r1 = client.post(
        "/v1/check",
        json={"key": key, "install_id": "ii-1", "version": "1.0"},
        headers={"X-Forwarded-For": "10.20.30.40"},
    )
    r2 = client.post(
        "/v1/check",
        json={"key": key, "install_id": "ii-1", "version": "1.0"},
        headers={"X-Forwarded-For": "11.22.33.44"},
    )
    assert r1.status_code == 200 and r2.status_code == 200

    # Pull the install row and assert ip_addr_hash didn't change between calls.
    from app.db import SessionLocal
    from app.models import Install
    with SessionLocal() as s:
        rows = s.query(Install).all()
        assert len(rows) == 1, f"expected single install row, got {len(rows)}"
        # The hash is of request.client.host (== 'testclient' under TestClient),
        # not of any XFF entry — so a single stable value across both requests.
        # Concrete value not asserted (TestClient host may vary by version);
        # the invariant is that it does NOT match the SHA-256 of '10.20.30.40'
        # or '11.22.33.44'.
        import hashlib
        for spoofed in ("10.20.30.40", "11.22.33.44"):
            assert rows[0].ip_addr_hash != hashlib.sha256(spoofed.encode()).hexdigest(), (
                f"ip_addr_hash matched a spoofed XFF value ({spoofed}); "
                f"XFF parsing was not actually dropped"
            )
```

- [ ] **Step 2: Run — verify failure**

```bash
pytest tests/test_phase2_authn.py::test_xff_header_does_not_affect_install_ip_hash -v
```

Expected: FAIL — current code reads leftmost XFF when peer is loopback. TestClient's peer reports as `testclient` (not 127.0.0.1) so this might actually pass today; if it does, broaden the test: hit `/v1/check` over a request that simulates Caddy-on-loopback by setting `app.config['SCOPE_CLIENT'] = ('127.0.0.1', 0)` via dependency override OR by directly calling `_client_ip_hash(request)` with a constructed request that has `client.host == '127.0.0.1'` and an XFF header. If TestClient cannot simulate the loopback condition, replace the test with a direct unit test of `_client_ip_hash`:

```python
def test_client_ip_hash_ignores_xff(monkeypatch):
    """_client_ip_hash must return SHA-256 of request.client.host,
    even when X-Forwarded-For is present and the peer is loopback."""
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
```

Pick the test shape that actually fails under current code; the unit test is the more reliable choice.

- [ ] **Step 3: Replace `_client_ip_hash` in `app/routers/api.py`**

Current implementation (lines 69-90):

```python
def _client_ip_hash(request: Request) -> str | None:
    if request.client is None:
        return None
    peer = request.client.host
    src = peer
    if peer in ("127.0.0.1", "::1") and "x-forwarded-for" in request.headers:
        xff = request.headers["x-forwarded-for"]
        first = next((p.strip() for p in xff.split(",") if p.strip()), None)
        if first:
            src = first
    return hashlib.sha256(src.encode()).hexdigest()
```

Replace with:

```python
def _client_ip_hash(request: Request) -> str | None:
    """SHA-256 of the immediate-peer IP. We never trust client-supplied
    X-Forwarded-For: Caddy *appends* XFF, so its leftmost entry is whatever
    the client sent — strictly worse than the socket peer. In our deploy
    Caddy is on 127.0.0.1, so request.client.host is the last-hop value
    set by the proxy; trust that and only that. Behind a multi-hop CDN a
    future reader will need to be added that explicitly trusts only the
    rightmost N entries from a configured proxy chain."""
    if request.client is None:
        return None
    return hashlib.sha256(request.client.host.encode()).hexdigest()
```

- [ ] **Step 4: Replace `client_ip` in `app/rate_limit.py`**

Current implementation (lines 32-45):

```python
def client_ip(request: Request) -> str:
    if request.client is None:
        return get_remote_address(request)
    peer = request.client.host
    if peer in ("127.0.0.1", "::1") and "x-forwarded-for" in request.headers:
        xff = request.headers["x-forwarded-for"]
        first = next((p.strip() for p in xff.split(",") if p.strip()), None)
        if first:
            return first
    return peer
```

Replace with:

```python
def client_ip(request: Request) -> str:
    """Rate-limit key. Mirrors _client_ip_hash in app.routers.api:
    request.client.host only — no XFF parsing. Caddy on loopback means
    request.client.host IS the last-hop IP. Any future multi-hop deploy
    should re-introduce a trusted-proxies-aware reader here AND in api.py
    together so the two derivations don't drift."""
    if request.client is None:
        return get_remote_address(request)
    return request.client.host
```

- [ ] **Step 5: Run the test**

```bash
pytest tests/test_phase2_authn.py -v -k "xff"
pytest -q
```

Both green.

- [ ] **Step 6: Commit**

```bash
git add app/routers/api.py app/rate_limit.py tests/test_phase2_authn.py
git commit -m "$(cat <<'EOF'
H1: drop X-Forwarded-For parsing; trust request.client.host

Caddy appends XFF rather than overwriting, so the leftmost entry was
attacker-controlled. We never have a legitimate multi-hop proxy chain
to interpret today, and request.client.host is already the last-hop
value set by Caddy on loopback. Strict simplification: read the peer
directly, kill the XFF branch in both _client_ip_hash and rate_limit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: H2 — JWT `kid` + `aud` claims

**Files:**
- Modify: `app/signing.py`
- Test: `tests/test_phase2_authn.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/test_phase2_authn.py`:

```python
# ---------- H2: JWT kid + aud claims ---------------------------------------


def test_jwt_carries_kid_and_aud_claims(client):
    """Issued JWTs must carry kid (product id, survives slug rename) and
    aud (product slug). Clients ignore unknown claims today; the new claims
    are advisory until clients opt in."""
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
    assert "aud" in claims, f"jwt missing aud: {claims}"
    assert claims["aud"] == "asm", f"aud should be product slug: {claims['aud']}"
    # kid is an opaque UUID — assert shape, not value.
    assert isinstance(claims["kid"], str) and len(claims["kid"]) >= 8, claims["kid"]
```

- [ ] **Step 2: Run — verify failure**

```bash
pytest tests/test_phase2_authn.py -v -k "kid_and_aud"
```

Expected: FAIL (current payload doesn't carry these claims).

- [ ] **Step 3: Add the claims in `app/signing.py::sign_license_jwt`**

Locate the `payload = {...}` dict and add the two new keys. The complete payload after the edit:

```python
    payload = {
        "iss": product.jwt_issuer,
        "kid": product.id,           # opaque per-product id; survives slug rename
        "aud": product.slug,         # informational; matches the iss style
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

- [ ] **Step 4: Run the test**

```bash
pytest tests/test_phase2_authn.py -v -k "kid_and_aud"
pytest -q
```

- [ ] **Step 5: Commit**

```bash
git add app/signing.py tests/test_phase2_authn.py
git commit -m "$(cat <<'EOF'
H2: add kid + aud claims to license JWTs

kid = product.id (opaque, survives slug rename, future-proofs key rotation).
aud = product.slug (informational, matches iss style). Clients ignore
unknown claims today; the new claims become useful once a client opts in
to per-product validation OR a future key-rotation flow needs to
disambiguate which key signed a token.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: H3 — KEK required in production

**Files:**
- Modify: `app/config.py` — new env var `LICENSE_SERVER_REQUIRE_KEK`.
- Modify: `app/main.py::_validate_secrets_at_boot` — hard exit when set + KEK unset.
- Modify: `app/keystore.py::encrypt_secret` — raise instead of passing plaintext through when required.
- Test: `tests/test_phase2_authn.py` (append).

- [ ] **Step 1: Write the failing tests**

These are **unit tests against `app.keystore` and `app.main._validate_secrets_at_boot`**, NOT TestClient-based — because `LICENSE_SERVER_REQUIRE_KEK=1` + no-KEK would trigger `sys.exit(78)` in the lifespan handler that TestClient drives, killing the test process. Use direct module reloads (mirrors the pattern in `conftest.py`):

Append:

```python
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
```

- [ ] **Step 2: Run — verify failure**

```bash
pytest tests/test_phase2_authn.py -v -k "require_kek"
```

Expected: 2 FAIL (the gate hasn't been implemented), 1 PASS (legacy path).

- [ ] **Step 3: Add the env-var to `app/config.py::Settings`**

In the `Settings` BaseModel, add a new bool field below `key_encryption_key_prev`:

```python
    # When True (LICENSE_SERVER_REQUIRE_KEK=1 in env), the server refuses to
    # store new secrets in plaintext. encrypt_secret() raises instead of
    # passing the value through, and boot fails fast if KEK is unset.
    require_kek: bool = False
```

In the `get_settings()` factory at the bottom of the file, add the reader:

```python
        require_kek=os.environ.get("LICENSE_SERVER_REQUIRE_KEK", "").lower() in ("1", "true", "yes"),
```

- [ ] **Step 4: Guard the boot validator in `app/main.py::_validate_secrets_at_boot`**

After the KEK warning block (the existing `if not s.key_encryption_key` branch), insert the strict-mode hard exit:

```python
    if s.require_kek and not s.key_encryption_key:
        log.critical(
            "LICENSE_SERVER_REQUIRE_KEK=1 set but LICENSE_KEY_ENCRYPTION_KEY is "
            "unset. Refusing to boot in plaintext-write mode. Generate a KEK "
            "with `python -c 'from cryptography.fernet import Fernet; print("
            "Fernet.generate_key().decode())'` and set it in the env."
        )
        sys.exit(78)  # EX_CONFIG
```

- [ ] **Step 5: Guard `app/keystore.py::encrypt_secret`**

Modify the function body so the no-KEK branch raises when `require_kek` is set. Current shape:

```python
def encrypt_secret(plaintext: str | None) -> str | None:
    if plaintext is None:
        return None
    if is_encrypted(plaintext):
        return plaintext
    f = _fernet()
    if f is None:
        return plaintext
    token = f.encrypt(plaintext.encode("utf-8"))
    return _PREFIX + token.decode("ascii")
```

Replace the `if f is None: return plaintext` line with:

```python
    if f is None:
        if get_settings().require_kek:
            raise RuntimeError(
                "KEK required (LICENSE_SERVER_REQUIRE_KEK=1) but "
                "LICENSE_KEY_ENCRYPTION_KEY is unset; refusing to write plaintext"
            )
        return plaintext
```

- [ ] **Step 6: Run the tests + full suite**

```bash
pytest tests/test_phase2_authn.py -v -k "require_kek"
pytest -q
```

- [ ] **Step 7: Commit**

```bash
git add app/config.py app/main.py app/keystore.py tests/test_phase2_authn.py
git commit -m "$(cat <<'EOF'
H3: LICENSE_SERVER_REQUIRE_KEK gate against plaintext secret writes

New env var; when set: boot validator hard-exits if LICENSE_KEY_ENCRYPTION_KEY
is unset; encrypt_secret raises instead of passing plaintext through. Default
(unset) preserves backwards-compatible plaintext fallthrough so a no-KEK dev
deploy keeps working. Production deploys should set this flag once they have
a KEK provisioned.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: H7a — TOTP enrolment + verify + disable + recovery codes

**Files:**
- Create: `app/services/mfa.py` — pure logic
- Create: `app/routers/admin_ui/mfa.py` — HTTP handlers
- Create: `app/templates/mfa.html` — settings page
- Create: `alembic/versions/<rev>_admin_mfa.py` — schema
- Modify: `app/models.py` — `AdminMfa` model
- Modify: `app/routers/admin_ui/__init__.py` — register router
- Modify: `app/templates/base.html` — sidebar entry
- Modify: `pyproject.toml` — add `pyotp` + `qrcode` deps
- Test: `tests/test_mfa.py` (new)

This is the largest task. Build piece by piece.

- [ ] **Step 1: Add deps**

Edit `pyproject.toml` — extend the `dependencies` list with two new entries:

```toml
    "pyotp>=2.9",
    "qrcode>=7.4",
```

Then install in your venv:

```bash
pip install -e ".[dev]"
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_mfa.py`:

```python
"""TOTP-based MFA on admin login. Tests cover the full enrolment + login flow."""
from __future__ import annotations

import re

import pyotp
from fastapi.testclient import TestClient


def _login(c: TestClient) -> dict[str, str]:
    r = c.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return {"ls_session": r.cookies["ls_session"]}


def _csrf(cookies: dict[str, str]) -> str:
    from app.config import get_settings
    from app.security import csrf_token
    return csrf_token(get_settings().session_secret, cookies["ls_session"])


def _post(c: TestClient, url: str, cookies: dict[str, str], data: dict | None = None, **kw):
    payload = dict(data or {})
    payload.setdefault("csrf_token", _csrf(cookies))
    return c.post(url, data=payload, cookies=cookies, **kw)


# ---------- enrol flow -----------------------------------------------------


def test_mfa_settings_page_renders_when_logged_in(client):
    cookies = _login(client)
    r = client.get("/admin/mfa", cookies=cookies, follow_redirects=False)
    assert r.status_code == 200, r.text
    assert b"MFA" in r.content or b"mfa" in r.content.lower()


def test_mfa_enrol_returns_provisioning_uri(client):
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies, follow_redirects=False)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["provisioning_uri"].startswith("otpauth://totp/"), body
    assert body["secret"] and re.match(r"^[A-Z2-7]+$", body["secret"]), body
    # not enabled yet — must verify with one OTP first
    from app.db import SessionLocal
    from app.models import AdminMfa
    with SessionLocal() as s:
        row = s.query(AdminMfa).first()
        assert row is not None and row.enabled is False, row


def test_mfa_verify_enrol_with_valid_code_enables_and_returns_recovery_codes(client):
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    otp = pyotp.TOTP(secret).now()
    r = _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": otp})
    assert r.status_code == 200, r.text
    body = r.json()
    codes = body["recovery_codes"]
    assert len(codes) == 10
    assert all(isinstance(c, str) and len(c) >= 8 for c in codes)
    # row now enabled
    from app.db import SessionLocal
    from app.models import AdminMfa
    with SessionLocal() as s:
        row = s.query(AdminMfa).first()
        assert row.enabled is True


def test_mfa_verify_enrol_with_wrong_code_rejected(client):
    cookies = _login(client)
    _post(client, "/admin/mfa/enroll", cookies)
    r = _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": "000000"})
    assert r.status_code == 400, r.text
    from app.db import SessionLocal
    from app.models import AdminMfa
    with SessionLocal() as s:
        row = s.query(AdminMfa).first()
        assert row.enabled is False


# ---------- disable -------------------------------------------------------


def test_mfa_disable_with_valid_otp(client):
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    # now disable
    r = _post(client, "/admin/mfa/disable", cookies, data={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    from app.db import SessionLocal
    from app.models import AdminMfa
    with SessionLocal() as s:
        row = s.query(AdminMfa).first()
        assert row.enabled is False


def test_mfa_disable_with_recovery_code(client):
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    enrol = _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    rcodes = enrol.json()["recovery_codes"]
    # Disable via recovery code (no OTP needed)
    r = _post(client, "/admin/mfa/disable", cookies, data={"code": rcodes[0]})
    assert r.status_code == 200, r.text


def test_mfa_disable_with_wrong_code_rejected(client):
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    r = _post(client, "/admin/mfa/disable", cookies, data={"code": "999999"})
    assert r.status_code == 400, r.text


# ---------- recovery codes invalidation ------------------------------------


def test_recovery_code_disable_wipes_all_state(client):
    """Disabling via a recovery code wipes the row's secret + ALL stored
    recovery hashes — the remaining codes from the same set are invalid
    too. (Login-flow single-use is exercised separately in Task 5 tests.)"""
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    enrol = _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    rcodes = enrol.json()["recovery_codes"]
    r = _post(client, "/admin/mfa/disable", cookies, data={"code": rcodes[0]})
    assert r.status_code == 200
    from app.db import SessionLocal
    from app.models import AdminMfa
    with SessionLocal() as s:
        row = s.query(AdminMfa).first()
        assert row.enabled == 0
        assert row.secret_encrypted is None
        assert row.recovery_codes_hashed is None
```

- [ ] **Step 3: Run — verify failure**

```bash
pytest tests/test_mfa.py -v
```

Expected: every test fails (table/routes don't exist).

- [ ] **Step 4: Schema — `AdminMfa` model**

In `app/models.py`, after the `ProcessedStripeEvent` model, add:

```python
class AdminMfa(Base):
    """Single-row table for the (single-operator) admin MFA state.

    `id == 1` is enforced by a CheckConstraint — we never want a second
    row, since "the admin" is one logical principal in this deployment
    shape. Multi-operator setups would graduate to a per-user table.
    """

    __tablename__ = "admin_mfa"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_admin_mfa_single_row"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    enabled: Mapped[bool] = mapped_column(Integer, default=0)
    # Fernet-encrypted TOTP base32 secret. Stored encrypted because anyone
    # with the secret can forge OTPs.
    secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    # JSON list of single-use recovery-code SHA-256 hex digests. When a code
    # is redeemed it's removed from the list (re-saved). Fernet-wrapping the
    # list itself is overkill given each entry is already a one-way hash.
    recovery_codes_hashed: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow_naive)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
```

- [ ] **Step 5: Alembic migration**

```bash
alembic revision -m "admin_mfa table"
```

Edit the generated file:

```python
"""admin_mfa table

Revision ID: <keep generated>
Revises: 5c836611873a
Create Date: <keep generated>

Single-row table for admin MFA enrolment state. Default is empty (no row).
TOTP secret is stored Fernet-encrypted; recovery codes are stored as SHA-256
hex digests in a JSON list.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "<keep generated>"
down_revision: str | Sequence[str] | None = "5c836611873a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "admin_mfa",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("enabled", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("secret_encrypted", sa.Text, nullable=True),
        sa.Column("recovery_codes_hashed", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column("last_used_at", sa.DateTime, nullable=True),
        sa.CheckConstraint("id = 1", name="ck_admin_mfa_single_row"),
    )


def downgrade() -> None:
    op.drop_table("admin_mfa")
```

- [ ] **Step 6: Pure logic — `app/services/mfa.py`**

```python
"""TOTP MFA business logic — pure functions, no FastAPI types.

Secret + recovery codes live in the DB (`admin_mfa` table). Secret is
Fernet-encrypted (anyone with it can forge OTPs); recovery codes are stored
as SHA-256 hex digests (one-way; we can verify a candidate but not recover
the plaintext). Single-row table, `id == 1` enforced by check constraint.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass

import pyotp
from sqlalchemy.orm import Session

from app._time import utcnow
from app.keystore import decrypt_secret, encrypt_secret
from app.models import AdminMfa

ISSUER = "YgLicenseServer"
ACCOUNT = "admin"
RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_BYTES = 6  # ~12 base32 chars => ~58 bits, plenty for one-use


@dataclass(frozen=True)
class EnrolStart:
    secret: str
    provisioning_uri: str


def _row(db: Session) -> AdminMfa | None:
    return db.query(AdminMfa).filter_by(id=1).one_or_none()


def get_state(db: Session) -> AdminMfa | None:
    """Returns the row if present; None if MFA has never been enrolled."""
    return _row(db)


def is_enabled(db: Session) -> bool:
    row = _row(db)
    return bool(row and row.enabled)


def start_enrol(db: Session) -> EnrolStart:
    """Generate a fresh base32 TOTP secret, store it Fernet-encrypted on
    the (new or existing) admin_mfa row with enabled=False. Returns the
    plaintext secret and the otpauth:// provisioning URI for the caller
    to render as a QR code."""
    secret = pyotp.random_base32()
    enc = encrypt_secret(secret)
    row = _row(db)
    if row is None:
        row = AdminMfa(id=1, enabled=0, secret_encrypted=enc)
        db.add(row)
    else:
        row.enabled = 0
        row.secret_encrypted = enc
        row.recovery_codes_hashed = None
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=ACCOUNT, issuer_name=ISSUER)
    return EnrolStart(secret=secret, provisioning_uri=uri)


def verify_enrol(db: Session, code: str) -> list[str] | None:
    """Verify a TOTP code against the pending enrolment. On success, flip
    enabled=True, generate + store + return recovery codes. Returns None
    on bad code (caller emits 400)."""
    row = _row(db)
    if row is None or row.secret_encrypted is None or row.enabled:
        return None
    secret = decrypt_secret(row.secret_encrypted)
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        return None
    codes = _generate_recovery_codes()
    row.enabled = 1
    row.recovery_codes_hashed = json.dumps([_hash(c) for c in codes])
    db.commit()
    return codes


def verify_login(db: Session, code: str) -> bool:
    """Verify either a TOTP code or a recovery code. Recovery codes are
    single-use: redeemed codes are removed from the stored list. Returns
    True on success, False otherwise."""
    row = _row(db)
    if row is None or not row.enabled or row.secret_encrypted is None:
        return False
    # Try TOTP first (cheap).
    secret = decrypt_secret(row.secret_encrypted)
    if pyotp.TOTP(secret).verify(code, valid_window=1):
        row.last_used_at = utcnow()
        db.commit()
        return True
    # Fallback to recovery codes (case-insensitive match, then single-use).
    stored = json.loads(row.recovery_codes_hashed or "[]")
    candidate = _hash(code.strip().upper())
    if candidate not in stored:
        return False
    stored.remove(candidate)
    row.recovery_codes_hashed = json.dumps(stored)
    row.last_used_at = utcnow()
    db.commit()
    return True


def disable(db: Session, code: str) -> bool:
    """Verify the supplied OTP or recovery code, then clear all MFA state.
    Returns True on success."""
    if not verify_login(db, code):
        return False
    row = _row(db)
    if row is None:
        return False
    row.enabled = 0
    row.secret_encrypted = None
    row.recovery_codes_hashed = None
    db.commit()
    return True


def regen_recovery(db: Session, code: str) -> list[str] | None:
    """Verify the supplied OTP, then generate + store + return a fresh
    set of recovery codes. Old codes are invalidated."""
    row = _row(db)
    if row is None or not row.enabled or row.secret_encrypted is None:
        return None
    secret = decrypt_secret(row.secret_encrypted)
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        return None
    codes = _generate_recovery_codes()
    row.recovery_codes_hashed = json.dumps([_hash(c) for c in codes])
    db.commit()
    return codes


def _generate_recovery_codes() -> list[str]:
    """Generate N base32 recovery codes. Uppercase + numeric only so they
    survive copy/paste through email and terminals without ambiguity."""
    return [secrets.token_hex(RECOVERY_CODE_BYTES).upper() for _ in range(RECOVERY_CODE_COUNT)]


def _hash(code: str) -> str:
    """SHA-256 hex digest. Codes are uppercase + hex, so case is unambiguous;
    we still .upper() at verify time as a defensive step."""
    return hashlib.sha256(code.upper().encode()).hexdigest()
```

- [ ] **Step 7: HTTP handlers — `app/routers/admin_ui/mfa.py`**

```python
"""Admin MFA enrolment + management routes.

GET  /admin/mfa                — settings page
POST /admin/mfa/enroll         — generate secret + provisioning URI
POST /admin/mfa/verify-enroll  — confirm with one OTP, enable, return recovery codes
POST /admin/mfa/disable        — accept OTP or recovery code, clear MFA state
POST /admin/mfa/regen-recovery — replace the recovery-code set (requires OTP)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy.orm import Session

from app.db import get_db
from app.routers.admin_ui._deps import require_csrf, require_login, templates
from app.services import mfa as mfa_svc

router = APIRouter()


@router.get("/admin/mfa", response_class=HTMLResponse)
def mfa_page(request: Request, db: Session = Depends(get_db)) -> Response:
    require_login(request)
    state = mfa_svc.get_state(db)
    return templates.TemplateResponse(
        request, "mfa.html",
        {"enabled": bool(state and state.enabled)},
    )


@router.post("/admin/mfa/enroll")
def mfa_enroll(
    request: Request, csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    start = mfa_svc.start_enrol(db)
    return JSONResponse({"secret": start.secret, "provisioning_uri": start.provisioning_uri})


@router.post("/admin/mfa/verify-enroll")
def mfa_verify_enroll(
    request: Request, code: str = Form(...), csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    codes = mfa_svc.verify_enrol(db, code)
    if codes is None:
        return JSONResponse({"error": "invalid code"}, status_code=400)
    return JSONResponse({"recovery_codes": codes})


@router.post("/admin/mfa/disable")
def mfa_disable(
    request: Request, code: str = Form(...), csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    if not mfa_svc.disable(db, code):
        return JSONResponse({"error": "invalid code"}, status_code=400)
    return JSONResponse({"ok": True})


@router.post("/admin/mfa/regen-recovery")
def mfa_regen_recovery(
    request: Request, code: str = Form(...), csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    codes = mfa_svc.regen_recovery(db, code)
    if codes is None:
        return JSONResponse({"error": "invalid code"}, status_code=400)
    return JSONResponse({"recovery_codes": codes})
```

- [ ] **Step 8: Register the router**

Edit `app/routers/admin_ui/__init__.py` — add `mfa` to imports + `ALL_ROUTERS`:

```python
from app.routers.admin_ui import (
    auth,
    customers,
    dashboard,
    events,
    licenses,
    mfa,  # NEW
    products,
    webhook_deliveries,
)

ALL_ROUTERS = [
    auth.router,
    dashboard.router,
    products.router,
    licenses.router,
    customers.router,
    events.router,
    webhook_deliveries.router,
    mfa.router,  # NEW
]
```

- [ ] **Step 9: Settings template — `app/templates/mfa.html`**

```html
{% extends "base.html" %}
{% block title %}MFA{% endblock %}
{% block topbar_title %}Multi-Factor Authentication{% endblock %}
{% block content %}
<div class="card">
  <h2 style="margin-top:0;">Admin MFA</h2>

  {% if enabled %}
    <p>Status: <span class="badge active">Enabled</span></p>
    <p class="muted">An attacker with the admin token still has to provide a TOTP code on every login. Keep your recovery codes in a password manager.</p>
    <h3>Regenerate Recovery Codes</h3>
    <form id="regen-form">
      {{ csrf_input(request) }}
      <label>Current OTP code</label>
      <input name="code" required autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}">
      <button type="submit" class="btn">Generate new codes</button>
    </form>
    <h3 style="margin-top:1.5em;">Disable MFA</h3>
    <form id="disable-form">
      {{ csrf_input(request) }}
      <label>OTP code or recovery code</label>
      <input name="code" required autocomplete="one-time-code">
      <button type="submit" class="btn danger">Disable</button>
    </form>
  {% else %}
    <p>Status: <span class="badge revoked">Not enabled</span></p>
    <p class="muted">Adding TOTP MFA means an attacker with the admin token still has to provide a one-time code on every login. Use an authenticator app (Google Authenticator, Authy, 1Password, etc.).</p>
    <button type="button" id="start-enrol" class="btn">Start enrolment</button>
    <div id="enrol-step" style="display:none;margin-top:1em;">
      <p>Scan this URI with your authenticator app:</p>
      <pre id="prov-uri" style="word-break:break-all;"></pre>
      <p class="muted">Or enter this secret manually: <code id="secret"></code></p>
      <form id="verify-form" style="margin-top:1em;">
        {{ csrf_input(request) }}
        <label>Enter the 6-digit code from your app</label>
        <input name="code" required autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}">
        <button type="submit" class="btn">Verify + enable</button>
      </form>
    </div>
    <div id="codes-step" style="display:none;margin-top:1em;">
      <h3>Recovery codes</h3>
      <p class="muted">Save these somewhere safe. Each can be used once if you lose your authenticator.</p>
      <pre id="codes"></pre>
    </div>
  {% endif %}
</div>
<script>
(function () {
  async function postForm(url, formEl) {
    const fd = new FormData(formEl);
    const r = await fetch(url, { method: 'POST', body: fd, credentials: 'same-origin' });
    return [r.status, await r.json()];
  }
  const start = document.getElementById('start-enrol');
  if (start) start.addEventListener('click', async () => {
    const fd = new FormData();
    fd.append('csrf_token', document.querySelector('input[name=csrf_token]').value);
    const r = await fetch('/admin/mfa/enroll', { method: 'POST', body: fd, credentials: 'same-origin' });
    const d = await r.json();
    document.getElementById('prov-uri').textContent = d.provisioning_uri;
    document.getElementById('secret').textContent = d.secret;
    document.getElementById('enrol-step').style.display = '';
  });
  const verify = document.getElementById('verify-form');
  if (verify) verify.addEventListener('submit', async (e) => {
    e.preventDefault();
    const [status, d] = await postForm('/admin/mfa/verify-enroll', verify);
    if (status === 200) {
      document.getElementById('codes').textContent = d.recovery_codes.join('\n');
      document.getElementById('codes-step').style.display = '';
      verify.style.display = 'none';
    } else {
      alert(d.error || 'Verification failed');
    }
  });
  const disable = document.getElementById('disable-form');
  if (disable) disable.addEventListener('submit', async (e) => {
    e.preventDefault();
    const [status, d] = await postForm('/admin/mfa/disable', disable);
    if (status === 200) location.reload();
    else alert(d.error || 'Disable failed');
  });
  const regen = document.getElementById('regen-form');
  if (regen) regen.addEventListener('submit', async (e) => {
    e.preventDefault();
    const [status, d] = await postForm('/admin/mfa/regen-recovery', regen);
    if (status === 200) {
      alert('New recovery codes:\n\n' + d.recovery_codes.join('\n'));
    } else alert(d.error || 'Regen failed');
  });
})();
</script>
{% endblock %}
```

- [ ] **Step 10: Sidebar entry — `app/templates/base.html`**

Find the existing `.sidebar-nav` block (around line 235-268) and add a new link between `events` and `webhook-deliveries`:

```html
      <a href="/admin/mfa" data-nav-key="mfa" title="MFA">
        <svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
          <path d="M8 1a2 2 0 0 0-2 2v4H5a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-1V3a2 2 0 0 0-2-2zm3 6V3a1 1 0 1 0-2 0v4z" transform="translate(0,0)"/>
        </svg>
        <span class="nav-label">MFA</span>
      </a>
```

Also extend the route-key matcher in `app/static/admin.js` (the `routes` object inside `ready(function () { ... })`) to include `'mfa'`:

```javascript
    'mfa':                 function (p) { return p.indexOf('/admin/mfa') === 0; },
```

- [ ] **Step 11: Run the tests + full suite**

```bash
pytest tests/test_mfa.py -v
pytest -q
```

All tests in `test_mfa.py` should pass. Note: the existing `tests/conftest.py` reloads many modules; if the new `mfa` services / templates fail to import you may need to add them to the reload chain. Specifically add to `_build_client` in `conftest.py`:

```python
    import app.services.mfa as svc_mfa
    importlib.reload(svc_mfa)
    import app.routers.admin_ui.mfa as ui_mfa
    importlib.reload(ui_mfa)
```

- [ ] **Step 12: Commit**

```bash
git add app/models.py app/services/mfa.py app/routers/admin_ui/mfa.py app/routers/admin_ui/__init__.py app/templates/mfa.html app/templates/base.html app/static/admin.js alembic/versions/*_admin_mfa.py tests/test_mfa.py tests/conftest.py pyproject.toml
git commit -m "$(cat <<'EOF'
H7a: TOTP MFA enrolment + verify + disable + recovery codes

New admin_mfa single-row table (Fernet-encrypted secret, SHA-256-hashed
recovery codes). Service layer in app.services.mfa: start_enrol,
verify_enrol, verify_login, disable, regen_recovery. HTTP routes mounted
under /admin/mfa with the existing session + CSRF guards. Recovery codes
are single-use, removed from the stored list on redemption. Login flow
integration lands in the next commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: H7b — Login flow integration (pre-MFA cookie)

**Files:**
- Create: `app/templates/login_mfa.html`
- Modify: `app/routers/admin_ui/_deps.py` — `PRE_MFA_COOKIE` constant + helper.
- Modify: `app/routers/admin_ui/auth.py::login` — split into first-factor + MFA-step.
- Test: `tests/test_mfa.py` (append login-flow tests)

- [ ] **Step 1: Write failing tests**

Append to `tests/test_mfa.py`:

```python
# ---------- login flow integration -----------------------------------------


def test_login_without_mfa_works_as_before(client):
    """With no MFA row (or enabled=False), POST /admin/login lands at /admin."""
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/admin"


def test_login_with_mfa_enabled_redirects_to_mfa_step(client):
    """When admin_mfa.enabled=True, POST /admin/login lands at /admin/login/mfa
    with a pre-mfa cookie (NOT the full session cookie yet)."""
    # First: enrol + enable MFA.
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    # Now log out and log back in.
    client.cookies.clear()
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    assert r.headers["location"] == "/admin/login/mfa"
    assert "ls_pre_mfa" in r.cookies
    assert "ls_session" not in r.cookies


def test_login_mfa_step_completes_with_valid_otp(client):
    """The MFA-step POST swaps the pre-mfa cookie for a full session cookie."""
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    client.cookies.clear()
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    pre_cookie = {"ls_pre_mfa": r.cookies["ls_pre_mfa"]}
    code = pyotp.TOTP(secret).now()
    r = client.post(
        "/admin/login/mfa",
        data={"code": code},
        cookies=pre_cookie, follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    assert r.headers["location"] == "/admin"
    assert "ls_session" in r.cookies


def test_login_mfa_step_rejects_bad_code(client):
    cookies = _login(client)
    r = _post(client, "/admin/mfa/enroll", cookies)
    secret = r.json()["secret"]
    _post(client, "/admin/mfa/verify-enroll", cookies, data={"code": pyotp.TOTP(secret).now()})
    client.cookies.clear()
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    pre_cookie = {"ls_pre_mfa": r.cookies["ls_pre_mfa"]}
    r = client.post(
        "/admin/login/mfa", data={"code": "000000"},
        cookies=pre_cookie, follow_redirects=False,
    )
    # Stays on the MFA step with an error flag.
    assert r.status_code == 303
    assert r.headers["location"].startswith("/admin/login/mfa")
```

- [ ] **Step 2: Run — verify failure**

```bash
pytest tests/test_mfa.py -v -k "login"
```

- [ ] **Step 3: Add the `ls_pre_mfa` cookie helpers in `app/routers/admin_ui/_deps.py`**

Below `SESSION_COOKIE = "ls_session"` add:

```python
PRE_MFA_COOKIE = "ls_pre_mfa"
PRE_MFA_MAX_AGE_SECONDS = 5 * 60  # 5 min window to enter the OTP


def pre_mfa_serializer() -> URLSafeSerializer:
    """Separate serializer salt for the pre-MFA cookie so a session-cookie
    leak cannot be replayed as a pre-MFA cookie or vice versa."""
    s = get_settings()
    if not s.session_secret:
        raise HTTPException(status_code=503, detail="SESSION_SECRET not set")
    return URLSafeSerializer(s.session_secret, salt="admin-pre-mfa")


def pre_mfa_valid(request: Request) -> bool:
    raw = request.cookies.get(PRE_MFA_COOKIE)
    if not raw:
        return False
    try:
        data = pre_mfa_serializer().loads(raw)
    except BadSignature:
        return False
    iat = data.get("iat") if isinstance(data, dict) else None
    if not isinstance(iat, int):
        return False
    return (int(time.time()) - iat) <= PRE_MFA_MAX_AGE_SECONDS
```

- [ ] **Step 4: Split the login handler in `app/routers/admin_ui/auth.py`**

Replace the existing `login` function body so that after first-factor success it checks the MFA flag and branches. Updated full file:

```python
"""Login / logout + root redirect."""
from __future__ import annotations

import secrets
import time

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import get_db
from app.rate_limit import limiter
from app.routers.admin_ui._deps import (
    PRE_MFA_COOKIE,
    PRE_MFA_MAX_AGE_SECONDS,
    SESSION_COOKIE,
    SESSION_MAX_AGE_SECONDS,
    pre_mfa_serializer,
    pre_mfa_valid,
    require_csrf,
    serializer,
    templates,
)
from app.services import mfa as mfa_svc

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def root(request: Request) -> Response:
    return RedirectResponse("/admin", status_code=303)


@router.get("/admin/login", response_class=HTMLResponse)
def login_form(request: Request, error: str | None = None) -> Response:
    return templates.TemplateResponse(request, "login.html", {"error": error})


@router.post("/admin/login")
@limiter.limit("10/minute")
def login(
    request: Request,
    token: str = Form(...),
    s: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> Response:
    if not s.admin_token:
        raise HTTPException(status_code=503, detail="ADMIN_TOKEN not set")
    if not secrets.compare_digest(token, s.admin_token):
        return RedirectResponse("/admin/login?error=invalid", status_code=303)
    if mfa_svc.is_enabled(db):
        # First factor ok; set a short-lived pre-MFA cookie and route to
        # the second-factor entry page. The pre-MFA cookie is NOT a session
        # — it cannot access any /admin/* page except /admin/login/mfa.
        pre = pre_mfa_serializer().dumps({"ok": True, "iat": int(time.time())})
        resp = RedirectResponse("/admin/login/mfa", status_code=303)
        resp.set_cookie(
            PRE_MFA_COOKIE, pre,
            httponly=True, secure=s.cookie_secure, samesite="lax",
            max_age=PRE_MFA_MAX_AGE_SECONDS,
        )
        return resp
    # No MFA: original single-factor flow.
    cookie = serializer().dumps({"ok": True, "iat": int(time.time())})
    resp = RedirectResponse("/admin", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE, cookie,
        httponly=True, secure=s.cookie_secure, samesite="lax",
        max_age=SESSION_MAX_AGE_SECONDS,
    )
    return resp


@router.get("/admin/login/mfa", response_class=HTMLResponse)
def login_mfa_form(request: Request, error: str | None = None) -> Response:
    if not pre_mfa_valid(request):
        return RedirectResponse("/admin/login", status_code=303)
    return templates.TemplateResponse(request, "login_mfa.html", {"error": error})


@router.post("/admin/login/mfa")
@limiter.limit("10/minute")
def login_mfa(
    request: Request, code: str = Form(...),
    s: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> Response:
    if not pre_mfa_valid(request):
        return RedirectResponse("/admin/login", status_code=303)
    if not mfa_svc.verify_login(db, code):
        return RedirectResponse("/admin/login/mfa?error=invalid", status_code=303)
    # Promote pre-MFA → full session.
    cookie = serializer().dumps({"ok": True, "iat": int(time.time())})
    resp = RedirectResponse("/admin", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE, cookie,
        httponly=True, secure=s.cookie_secure, samesite="lax",
        max_age=SESSION_MAX_AGE_SECONDS,
    )
    resp.delete_cookie(PRE_MFA_COOKIE)
    return resp


@router.post("/admin/logout")
def logout(request: Request, csrf_token: str = Form("")) -> Response:
    require_csrf(request, csrf_token)
    resp = RedirectResponse("/admin/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp
```

- [ ] **Step 5: Add the MFA-step template — `app/templates/login_mfa.html`**

```html
{% extends "base.html" %}
{% block title %}MFA — Verify{% endblock %}
{% block content %}
<div style="max-width:380px;margin:6em auto;">
  <h2>Multi-Factor Authentication</h2>
  {% if error %}<div class="error">invalid code, try again</div>{% endif %}
  <form method="post" action="/admin/login/mfa" class="card">
    <label for="code">6-digit code (or recovery code)</label>
    <input id="code" name="code" type="text" autofocus required autocomplete="one-time-code">
    <button type="submit" style="margin-top:1em;width:100%;">Verify</button>
  </form>
  <p class="muted" style="text-align:center;font-size:.85em;">
    enter the code from your authenticator app, or one of your 10 recovery codes
  </p>
</div>
{% endblock %}
```

- [ ] **Step 6: Run tests + full suite**

```bash
pytest tests/test_mfa.py -v
pytest -q
```

- [ ] **Step 7: Commit**

```bash
git add app/routers/admin_ui/auth.py app/routers/admin_ui/_deps.py app/templates/login_mfa.html tests/test_mfa.py
git commit -m "$(cat <<'EOF'
H7b: login flow split for TOTP MFA

POST /admin/login now branches on admin_mfa.enabled: when on, sets a
5-minute pre-MFA cookie and redirects to /admin/login/mfa. The pre-MFA
cookie carries no admin authority — only the MFA-step endpoint accepts
it. Successful OTP swap promotes pre-MFA into the full session cookie.
No-MFA deploys keep the original single-redirect flow.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Version bump to v0.22.0

**Files:**
- Modify: `app/__init__.py` → `"0.22.0"`
- Modify: `pyproject.toml` → `version = "0.22.0"`

- [ ] **Step 1: Bump both files**

```python
# app/__init__.py
__version__ = "0.22.0"
```

```toml
# pyproject.toml
version = "0.22.0"
```

- [ ] **Step 2: Run full suite**

```bash
pytest -q
```

- [ ] **Step 3: Commit**

```bash
git add app/__init__.py pyproject.toml
git commit -m "$(cat <<'EOF'
chore: bump version to 0.22.0

Phase 2 authn + crypto hardening: H1 (XFF dropped), H2 (JWT kid/aud),
H3 (KEK-required gate), H7 (TOTP MFA on admin login).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## End-of-phase check

- [ ] `pytest -q` final green.
- [ ] `alembic upgrade head` on a fresh sqlite to confirm both Phase 1 + Phase 2 migrations chain cleanly.
- [ ] Confirm the admin UI's `/admin/mfa` page renders for a freshly-deployed instance with no MFA enrolled.

After Phase 2: Phase 3 (network/deploy hardening — Caddyfile, HTTPS-only webhooks) plan will be written.
