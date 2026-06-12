# Changelog

## v1.1.0 — first-class AI feature keys (`ai_api_included`, `ai_included_usd_cap`)

ASM's license-bundled AI auto-provisioning reads two keys from the license
JWT's `features` dict: `ai_api_included` (bool — gates the "use platform AI
key" path) and `ai_included_usd_cap` (number, optional — default monthly USD
allowance). Both were already expressible via the free-form features JSON;
this release gives them first-class authoring:

- **Admin UI license modal** — "AI included (platform key)" checkbox +
  "Monthly USD cap" number input (enabled only while ticked; empty = no
  cap). The edit prefill moves the two keys out of the Features (JSON)
  field into the dedicated controls; on save the controls win over
  hand-typed JSON.
- **Explicit `false` on toggle-off.** Un-ticking the checkbox saves
  `ai_api_included: false` rather than removing the key — ASM treats absent
  as false, but explicit false reads better in audit trails and decoded
  JWTs.
- **JSON API** — `POST /v1/admin/products/{slug}/licenses` accepts optional
  `ai_api_included` / `ai_included_usd_cap` fields that override the
  `features` dict. Omitted = `features` stays authoritative (back-compat).
  Cap without toggle, cap ≤ 0, or non-finite cap → 400.
- **Renewals preserve the keys** — Stripe `invoice.paid` extends the
  existing license row, leaving `features` untouched; now pinned by test.
- **Test-infra fix:** `tests/conftest.py` reload chain was missing
  `app.license_keys`, so non-alphabetical test subsets could pin a stale
  `get_settings` and die with "LICENSE_KEY_PEPPER is unset".

No schema or wire-format changes (`features` was already a JSON column);
safe drop-in upgrade from v1.0.5. The plaintext-`key`-column drop slated
for v1.1 did NOT happen in this release; comments updated.

## v1.0.5 — browser tab title shows active tab

- **`app/templates/base.html`** — `<title>` now renders as
  `YgLicenseServer - <Tab>` (Dashboard, Customers, Events, …) instead of
  just the tab name, so the Chrome tab is identifiable when switching
  between sections / multiple browser tabs.

## v1.0.4 — VM systemd timer fix

Config-only release. The container image is byte-identical to v1.0.3; this
bump exists so the deployed VM-config (under `deploy/gcp/`) and the tagged
release move together.

- **`deploy/gcp/yg-license-retry-webhooks.service`,
  `yg-license-expiry-warnings.service`,
  `yg-license-prune-events.service`** — added `--entrypoint python` to the
  `docker run` command. The image's `docker-entrypoint.sh` exec's
  `uvicorn app.main:app …` and was eating the timer's `-m app.scripts.X`
  args, exiting with `Error: No such option '-m'.` on every fire. The
  retry queue never recovered failed deliveries — only in-process
  BackgroundTasks dispatch (which works on the happy path) was actually
  delivering. Surfaced via the WO-tracker v1.0.3 LS-side smoke.
- **`scripts/smoke_v1_0_3.py`** added — self-contained prod smoke that
  surfaced the bug. Reusable for future point-releases.

VM-side, the fixed unit files were `scp`-installed + `daemon-reload`-ed
out-of-band; this release tags the source of truth so VM rebuilds pick
them up.

## v1.0.3 — webhook source UX + heartbeat resilience

Polish pass driven by the WorkoutTracker v1.0 compat findings (see
[`docs/v1.0-workouttracker-client-findings.md`](docs/v1.0-workouttracker-client-findings.md)).

- **`/v1/check` no longer 409s on a `public_url` mismatch against an
  admin-set URL.** The heartbeat continues, JWT is minted, URL stays
  unchanged, and an `Event` row of type `webhook:override_refused` records
  the attempt. Previously a client that hardcoded a `public_url` and ran
  into an admin-set license fell into grace + got blocked because every
  heartbeat failed.
- **`webhook_url_source` surfaces in the admin UI** as a small badge
  (`admin` / `self`) next to the webhook URL field. A muted hint below
  spells out whether the secret is echoed via `/v1/check` and whether
  client overrides are honored.
- **"Convert to self" admin button.** Visible in the license-edit modal
  only when `source='admin'` + a URL is set. One click: keeps the URL,
  flips source to `self`, rotates the secret (so the new one will be
  echoed via `/v1/check`). Old admin-distributed secret is invalidated.
- **New doc:** [`docs/v1.0-client-compat.md`](docs/v1.0-client-compat.md)
  consolidates the v1.0 client-side integration concerns (aud claim,
  webhook self-register, key-display semantics, kid claim).
- **CHANGELOG v1.0.0 entry backfilled** with the webhook URL-source split
  (previously only the aud + key-storage breaking changes were listed).

No schema or wire-format changes; safe drop-in upgrade from v1.0.2.

## v1.0.2 — MFA enrolment QR code

`/admin/mfa` now renders a scannable QR code alongside the otpauth URI and
the raw base32 secret. The QR is server-generated inline SVG (`qrcode` lib,
no pillow/raster path, no client-side JS lib). The "I can't scan" fallback —
URI + manual secret — moves into a collapsed `<details>` block.

Adds `qrcode>=7.4` as a runtime dep. No schema or wire-format changes.

## v1.0.1 — admin-UI issuance UX

Two bugs surfaced during the v1.0.0 smoke test:

- **Banner placement.** The post-issuance green flash with the plaintext key
  rendered on the parent page, hidden under the auto-opened edit modal —
  unusable. The key now lives inside the modal's Key field with its own
  Copy-to-clipboard button. On any subsequent page load the field shows only
  the truncated display form and the Copy button hides.
- **No customer email.** UI issuance was passing `send_email=False` to the
  service, so the Resend dispatch never fired (JSON API has always sent on
  issue). Fixed.

No schema or wire-format changes; safe drop-in upgrade from v1.0.0.

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

### Webhook URL source split (`admin` vs `self`)

Licenses gained a `webhook_url_source` column (`'admin'` | `'self'`,
default `'self'`). Provenance affects two policies on `/v1/check`:

- **Secret echo.** When `source='admin'`, the `/v1/check` response field
  `webhook_secret` is always `null`. The signing secret only round-trips
  to the client for self-registered URLs. Pre-v1.0 clients that persisted
  the echoed secret from `/v1/check` must either (a) re-fetch the secret
  via the admin-UI one-time display and bake it in, or (b) self-register
  by sending `public_url` on `/v1/check` (the URL must be unset on the
  server side first, or the operator must use the new "Convert to self"
  button — see v1.0.3 below).
- **Override lockout.** Prior to v1.0.3, `/v1/check` returned 409
  `webhook_url_locked` if a client sent a `public_url` that differed from
  an admin-set URL — the entire heartbeat failed. v1.0.3 softened this to
  log + audit-event only; see that release's notes.

See [`docs/v1.0-client-compat.md`](docs/v1.0-client-compat.md) for the
self-register integration pattern.

### Upgrade procedure

1. Generate a pepper and add `LICENSE_KEY_PEPPER=<hex>` to your env file.
2. (Optional but recommended) set `LICENSE_SERVER_REQUIRE_KEK=1` so the
   server hard-exits if either of KEK or pepper is missing.
3. Take a DB backup before upgrading. The migration backfills `key_hash` +
   `key_display` from the existing plaintext, then applies UNIQUE NOT NULL.
4. `./deploy.ps1` (or your equivalent) to ship the new image.
5. Update every client that decodes JWTs to pass `audience=product_slug`.
