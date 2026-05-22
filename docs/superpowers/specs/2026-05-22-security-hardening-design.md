# Security Hardening Pass — Design

**Date**: 2026-05-22
**Target versions**: 0.21.0 (phase 1), 0.22.0 (phase 2), 0.23.0 (phase 3), 1.0.0 (phase 4)
**Branch**: `yg/Vulnerabilities-21-5-2026`

## Goal

Close the three concrete vulnerabilities + eight hardening notes from the 2026-05-22 security review. Land in four semver-aligned phases on a single branch, one commit per fix, TDD.

## Scope

**In:**
- Vulns 1–3 (webhook hijack, DNS rebind, CSV injection).
- Hardening H1–H8 (XFF, JWT claims, KEK gate, latent bug, HTTPS-only webhooks, Caddyfile, TOTP MFA, at-rest key hashing).
- Pyproject version-drift fix (0.16.4 → match `app/__init__.py`).

**Out:**
- WebAuthn / passkey support (TOTP-only).
- Client-side anti-tamper / code-signing.
- Operator audit-log destination beyond existing `events` table.
- Multi-operator MFA / per-user admin accounts (still single shared bearer + MFA on top).

---

## Phase 1 — Critical vulns + latent bug (v0.21.0)

### Vuln 1 — webhook hijack + secret leak

**Data model:**
- New column `licenses.webhook_url_source` `String(16) NOT NULL DEFAULT 'self'`; values: `'admin'` | `'self'`.
- Set to `'admin'` whenever the URL is written via the admin UI or `/admin/api/licenses/{id}/webhook`.
- Set to `'self'` when written via `/v1/check`'s `public_url`.

**Behaviour change in `app/services/check.py::check_license`:**
- If `lic.webhook_url_source == 'admin'` and the incoming `public_url` differs, **refuse** the update with `CheckRejected("webhook_url_locked", http_status=409)`. Log + audit event.
- If accepted, write `webhook_url_source = 'self'`.

**Behaviour change in `CheckOut` response (`app/routers/api.py`):**
- `webhook_secret` is returned **only** when `lic.webhook_url_source == 'self'`.
- For admin-set URLs, the field is omitted (Pydantic `Optional[str] = None`).
- The lazy-mint at `services/check.py:78-79` is removed; the secret is minted only inside `apply_webhook_config()` when a URL is actually set.

**Audit:** On every URL-source flip or refused update, write an `Event(type="webhook:locked"|"webhook:self-registered", payload={previous_url, new_url, source})`.

**Alembic migration:** add column with default `'self'`. Then backfill: rows where `webhook_url IS NOT NULL` → `'admin'` (lock them down — they were configured deliberately, no reason for a license-key holder to be able to override). Rows where `webhook_url IS NULL` → keep `'self'` default. Admin can flip via UI on a per-license basis if they want client self-registration on a specific license.

### Vuln 2 — DNS-rebinding bypass of webhook SSRF guard

**Approach:** resolve once, connect by IP, set `Host` header + TLS SNI to the original hostname.

**Implementation in `app/webhooks.py::deliver`:**
1. Call `app.security.resolve_safe_address(url, allow_http=...)` → returns `(ip, port, scheme, original_host) | None`.
2. Build the actual request URL with the **literal IP** substituted for the hostname.
3. Pass `headers={"Host": original_host, ...}` and `extensions={"sni_hostname": original_host}` to `httpx.post`.

**New helper in `app/security.py::resolve_safe_address`:**
- Runs `is_safe_url_shape` (already exists).
- Calls `socket.getaddrinfo(host, port)`.
- Picks the first address that is `not _ip_is_private(addr)`. If none qualify → return `None`, caller refuses.
- Returns the resolved IP + hostname + scheme + port so the caller can pin.

**Edge cases:**
- IPv6: `httpx` accepts `https://[::1]/path`; the bracketing must be re-applied when substituting IP for host.
- Existing `is_safe_for_delivery` stays as a cheap pre-check for diagnostics / boot-time URL validation. The pin-and-connect path is the authoritative guard at delivery time.
- Cert validation: TLS verification against `original_host` (via SNI) is preserved.

### Vuln 3 — CSV injection

**New helper in `app/routers/exports.py::_csv_safe(v)`:**
```python
_UNSAFE = ("=", "+", "-", "@", "\t", "\r")
def _csv_safe(v):
    return (("'" + v) if (v and v[0] in _UNSAFE) else v)
```

**Applied to:**
- Every cell emitted by `app/routers/exports.py::_csv_stream` (wrap once in the generator).
- The hand-rolled CSV in `app/routers/admin_ui/events.py::events_csv`.

**Test corpus:** `customer.name = "=cmd|'/c calc'!A0"`, `customer.email = "+1@…"`, `event.payload = {"x": "@SUM(1+1)"}`, `event.note = "-1+1"`. Each round-trips as a literal cell (leading `'`) and parses without formula execution.

### H4 — implement missing `_fire_deleted_webhook`

`app/services/products.py:112` imports a symbol that does not exist in `app/services/licenses.py`. Build the function:

```python
def _fire_deleted_webhook(snapshot: _DeletedLicenseSnapshot) -> None:
    """Post-commit webhook fan-out for a deleted license. Opens a fresh
    session, enqueues a WebhookDelivery, calls attempt_in_fresh_session."""
    if not (snapshot.webhook_url and snapshot.webhook_secret):
        return
    from app.db import SessionLocal
    s = SessionLocal()
    try:
        d = wh.enqueue(
            s, url=snapshot.webhook_url, secret=snapshot.webhook_secret,
            event_type=wh.EVENT_DELETED,
            data={
                "license_id": snapshot.license_id, "license_key": snapshot.key,
                "key": snapshot.key, "product_slug": snapshot.product_slug,
                "customer_email": snapshot.customer_email,
            },
        )
        s.commit()
        wh.attempt_in_fresh_session(d.id)
    except Exception:
        s.rollback()
        log.exception("post-commit deleted-webhook failed")
    finally:
        s.close()
```

Add the regression test that exercises `delete_product` end-to-end with a webhook configured.

### Phase 1 commits

1. `H4: implement _fire_deleted_webhook (latent ImportError on delete_product)`
2. `Vuln 3: CSV-sanitize helper across all CSV writers`
3. `Vuln 2: DNS-pin webhook delivery (resolve once, connect by IP)`
4. `Vuln 1: webhook URL provenance + gated secret exposure`
5. `chore: bump version to 0.21.0`

Each fix-commit bumps both `pyproject.toml` and `app/__init__.py::__version__` — except H4, Vuln 3, Vuln 2, Vuln 1 which leave version alone and the final `chore` commit batches the bump. (This batching keeps individual fix commits free of unrelated edits while ensuring shipped main never has version drift.)

---

## Phase 2 — Authn + crypto hardening (v0.22.0)

### H3 — KEK required in production

- New env var `LICENSE_SERVER_REQUIRE_KEK` (parsed in `app/config.py` like `LICENSE_SERVER_REQUIRE_SECRETS`).
- When set:
  - Boot validator in `app/main.py::_validate_secrets_at_boot` calls `sys.exit(78)` if `key_encryption_key` is unset (same EX_CONFIG semantics as the existing strict check).
  - `app/keystore.py::encrypt_secret` raises `RuntimeError("KEK required but unset")` instead of silently passing plaintext through. Callers in `app/services/products.py` propagate as a 503.
- When unset → today's behaviour (warning only).

### H1 — XFF parsing

- `app/routers/api.py::_client_ip_hash` and `app/rate_limit.py::client_ip` rewritten to **always return `request.client.host`**. No XFF parsing.
- Rationale: in the documented deploy Caddy is the immediate peer on loopback, so `request.client.host` is *already* the trusted last-hop value. Reading any client-supplied header is strictly worse.
- If/when the deploy ever fronts a multi-hop CDN, the operator can re-introduce a `trusted_proxies`-aware reader. For now, the simpler stronger default wins.

### H2 — JWT `kid` + `aud`

`app/signing.py::sign_license_jwt` payload gains:
- `"kid": product.id` — opaque per-product id (UUID), survives slug rename.
- `"aud": product.slug` — informational, matches the `iss` style.

No header `kid` (PyJWT supports payload `kid` as a custom claim; we don't want a separate header). Client-side validation is unchanged; new claims are advisory until clients opt in.

### H7 — TOTP MFA on admin login

**Dependencies:** `pyotp>=2.9` added to `pyproject.toml`.

**Data model:** new table `admin_mfa`:
- `id` (PK, just `1` — single-row table since admin is single-tenant)
- `enabled` (bool)
- `secret_encrypted` (text, Fernet-wrapped under KEK)
- `recovery_codes_hashed` (JSON list of BLAKE2b digests, single-use)
- `created_at`, `last_used_at`

**Routes (`app/routers/admin_ui/mfa.py`, new):**
- `GET /admin/mfa` — landing page; shows enrolment QR (provisioning URI via pyotp) when disabled, "Disable" + recovery-code regenerate buttons when enabled.
- `POST /admin/mfa/enroll` — generates secret, stores encrypted, returns QR; the user must verify with one OTP code on the next step before `enabled` flips.
- `POST /admin/mfa/verify-enroll` — accepts `code`; if valid, flips `enabled=True`, generates 10 recovery codes, displays them once.
- `POST /admin/mfa/disable` — accepts current OTP code OR a recovery code; flips `enabled=False`.
- `POST /admin/mfa/regen-recovery` — accepts OTP; regenerates the 10 recovery codes.

**Login flow change (`app/routers/admin_ui/auth.py::login`):**
- Step 1: bearer-token verified → if `admin_mfa.enabled` is False, set session cookie + redirect to `/admin` (today's behaviour).
- Step 2: if enabled, set a **pre-mfa** cookie (separate signed cookie, 5-minute TTL, no admin access) and redirect to `/admin/login/mfa`.
- `GET /admin/login/mfa` — code-entry form. `POST /admin/login/mfa` validates OTP or recovery code; on success swap the pre-mfa cookie for the full session cookie.

**Rate limit:** `/admin/login/mfa` shares the existing `10/minute` IP limit. Recovery codes are single-use; once redeemed they're removed from the hashed list.

### Phase 2 commits

1. `H3: gate plaintext secret writes behind LICENSE_SERVER_REQUIRE_KEK`
2. `H1: drop XFF parsing; trust request.client.host`
3. `H2: add kid + aud JWT claims`
4. `H7: TOTP MFA on admin login`

---

## Phase 3 — Network / deploy hardening (v0.23.0)

### H6 — Caddyfile

```caddyfile
{
    email ${ADMIN_EMAIL}
    servers {
        trusted_proxies static private_ranges
    }
}

${LICENSE_HOST} {
    encode zstd gzip
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains"
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy no-referrer
        -Server
    }
    reverse_proxy 127.0.0.1:8800
    log { ... existing ... }
}
```

`trusted_proxies` here is belt-and-braces alongside H1's "trust loopback peer only" — even if a future change re-introduces XFF parsing, Caddy will strip spoofed entries.

### H5 — webhook HTTPS-only

- `app/security.py::is_safe_url_shape` default flips: `allow_http=False`.
- New per-license column `licenses.allow_http_webhook` `Bool NOT NULL DEFAULT FALSE`.
- Admin UI gains a checkbox under the webhook URL field: "Allow plain HTTP (LAN install only)".
- `apply_webhook_config` / `check_license` callers pass `allow_http=lic.allow_http_webhook` into the validator.
- Existing licenses with `http://` URLs get `allow_http_webhook=True` in the migration so behaviour doesn't regress; new URLs default to HTTPS-only.

### Pyproject drift fix

- Bump `pyproject.toml` `version` to `"0.23.0"`.
- Also touch `app/__init__.py::__version__`.
- One commit titled `chore: align pyproject version with __init__`.

### Phase 3 commits

1. `H6: Caddyfile trusted_proxies + security headers`
2. `H5: webhook HTTPS-only with per-license http opt-in`
3. `chore: align pyproject version`

---

## Phase 4 — At-rest license-key hashing (v1.0.0, breaking)

### Schema

New columns on `licenses`:
- `key_hash` `String(64) UNIQUE INDEX NOT NULL` — BLAKE2b-256 hex digest, keyed with server pepper.
- `key_display` `String(32) NOT NULL` — `<prefix>_<first-6-chars>…<last-4-chars>` (e.g. `asm_aB7cdE…XyZ9`). Always-safe to show in UI.

Existing `key` column retained for one release as deprecated. Drop in v1.1.0.

### Pepper

New env var `LICENSE_KEY_PEPPER` (32-byte base64). Fed into BLAKE2b's `key` argument. Required when `LICENSE_SERVER_REQUIRE_KEK=1`. Documented in `.env.example`.

### Lookup change

`app/services/check.py::check_license`:
```python
key_hash = hash_key(input_key)  # blake2b(input.encode(), key=pepper).hexdigest()
lic = db.query(License).filter_by(key_hash=key_hash).one_or_none()
```

### UI

- All license listings show `key_display` instead of `key`.
- The just-issued license modal still surfaces the **plaintext** key in the response of `POST /admin/products/{slug}/licenses` — that's the only place plaintext exists post-migration. The Stripe/Resend email path likewise gets it inline (the service returns plaintext from `issue_license`).
- Re-issue path is unchanged; the new key is shown once.

### Migration

`alembic/versions/<new>_license_key_hash.py`:
1. Add `key_hash`, `key_display`, both nullable.
2. For each existing row: compute `key_hash = blake2b(key.encode(), key=pepper)`, set `key_display = key[:key_prefix_len+1+6] + "…" + key[-4:]`.
3. Add `UNIQUE NOT NULL` constraints on the populated columns.
4. Leave `key` in place (deprecated).

Subsequent migration in v1.1 drops `key`.

### Breaking changes

- The admin UI **no longer shows full license keys for previously-issued licenses**. Document in CHANGELOG: "If you need the plaintext of a pre-1.0 license, grab it from your last DB backup; we can't reconstruct it from a hashed row."
- `/admin/exports/.../licenses.csv` likewise emits `key_display`. Plaintext is gone from CSV exports — that's actually a security improvement (no more "I downloaded the customer CSV and now my keys are on Dropbox").
- Custom client integrations that read `lic.key` from the DB directly need to switch to `key_hash` for lookups; plaintext is no longer there.

### Phase 4 commits

1. `H8: add key_hash + key_display schema + helper`
2. `H8: migrate /v1/check + admin UI to hashed lookup`
3. `H8: alembic migration to populate hash + display`
4. `docs: v1.0 changelog + upgrade notes`

---

## Test strategy

Per phase, per fix: TDD red-green.

- **Phase 1**:
  - `tests/test_security.py`: new tests for Vuln 1 (admin URL locked, secret hidden when admin-set), Vuln 2 (DNS-pin test via mocked resolver + mock httpx transport that asserts `Host` header + IP-target), Vuln 3 (parametrized CSV-escape test).
  - `tests/test_webhooks.py`: extend with `delete_product` cascade webhook fires (H4).
- **Phase 2**:
  - `tests/test_security.py`: KEK-required gate (boot exit + write refusal), XFF-ignored-now test, JWT-claims contain `kid`/`aud`.
  - `tests/test_mfa.py` (new): full TOTP flow — enrol, verify-enrol, login-with-OTP, login-with-recovery-code, recovery-codes-single-use, disable.
- **Phase 3**:
  - `tests/test_security.py`: webhook URL with `http://` rejected unless `allow_http_webhook=True`.
  - Caddyfile change is config-only; verified by `caddy validate` in CI (already wired).
- **Phase 4**:
  - `tests/test_check.py`: `/v1/check` accepts plaintext key, looks up by hash, returns JWT.
  - `tests/test_migrations.py`: stand up DB with pre-hash rows, run migration, assert key_hash + key_display populated and key still works.
  - `tests/test_exports.py`: CSV exports emit `key_display`, never plaintext.

## Rollout

- Per phase: bump version → push → CI green → ship via `deploy.ps1`.
- KEK rotation already supported via `LICENSE_KEY_ENCRYPTION_KEY_PREV` — no new mechanism for the new pepper (it's append-only; rotating it would require re-issuing every license).
- v1.0 needs a deploy-time backup of the DB *before* the hash migration runs. Document in `docs/deploy/gcp.md` and gate via a pre-migration warning in `docker-entrypoint.sh`.

## Resolved decisions

- Existing `http://` webhook URLs: auto-migrate to `allow_http=True`. New URLs default to HTTPS-only.
- Recovery-code count: 10.
- Pepper rotation: append-only. Documented in CHANGELOG; multi-version pepper deferred unless ops experience says otherwise.
- Webhook-source backfill: existing rows with `webhook_url IS NOT NULL` → `'admin'` (locked). NULL → `'self'`. Per-license flip via admin UI.
