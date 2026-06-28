# Changelog

## v1.4.8 — verified enable/disable webhook instancy; OFF→ON signature regression test

Verification pass (no production-code change) confirming that license enable/disable propagates
to a consumer install in **both** directions within ~1s, plus one regression test that locks the
previously-unpinned half.

The concern was that the outbound webhook emitter might be wired only into the disable/revoke
path (a common shape), so re-activating a license would propagate only on the next safety-net
poll. It is not: all three transitions (`enable_license`/`disable_license`/`revoke_license`)
funnel through the single `set_status()` choke-point, which enqueues a `license.status.changed`
delivery on **every** transition that has a webhook configured, and commits the state change
**before** the post-commit send so a receiver's immediate `/v1/check` reads the new state. Signing
(`X-License-Server-Signature: t=…,v1=<hmac-sha256-hex>` over `f"{t}." + raw_body`, single
serialization, fresh `t` re-signed per retry within the 300s window), verbatim callback-URL
storage (full `/api/license/webhook` path preserved), and the `/v1/check` 200-EdDSA-JWT /
401-blocking-reason contract were all re-confirmed against code and tests.

- **New regression test** `test_off_on_roundtrip_both_webhooks_verify_consumer_side` — toggles a
  throwaway license OFF then ON and asserts each toggle dispatches exactly one webhook to the
  verbatim registered URL that passes the consumer's byte-for-byte HMAC pseudocode inside the 300s
  window. The pre-existing signature self-test covered only the disable direction; this pins the
  **enable** direction's signature, the direction most likely to silently regress in a refactor.

No behavior change; no migration. Final cross-system confirmation (the consumer's
`license webhook verified` log on each toggle) remains an operator step — the consumer returns 200
even on a bad signature, so its HTTP status is never proof on its own.

## v1.4.7 — webhook delivery response observability (see what the receiver returned)

After configuring a webhook there was no way to tell from LS whether the receiver
is correctly set up with the matching signing secret — a delivery returned `200`
whether the HMAC verified or not, and the receiver's HTTP status wasn't even
recorded (`deliver()` returned it; `try_deliver()` threw it away). This adds the
industry-standard answer (Stripe/GitHub/Svix all ship a per-delivery log of what
the endpoint returned): record and surface the response.

- **`webhook_deliveries` records the receiver response** — two additive nullable
  columns, `response_status` (HTTP code on the last attempt; NULL = never reached
  the receiver — DNS/TLS/timeout/SSRF-refusal) and `response_excerpt` (response
  body, success or failure). `try_deliver()` now persists both on every attempt.
- **Test webhooks appear in the delivery log** — the "Test webhook" button now
  writes one terminal `WebhookDelivery` row (`license.test`, status
  `delivered`/`abandoned`, never queued for retry) so the test and its response
  are auditable alongside real deliveries.
- **Delivery-history page** gains a colour-coded **Response** column (2xx green /
  4xx amber / 5xx red / em-dash = never reached), with the response body excerpt
  in the cell tooltip — so a `401 bad signature` (the signal that the receiver's
  secret is wrong) is visible at a glance. The body is HTML-escaped; the signing
  secret is never rendered.

Additive Alembic migration (`a1f7c9e23b50`, auto-applied on boot). No API change.
The secret signature `test_webhook(lic)` becomes `test_webhook(lic, db)` (internal).

## v1.4.6 — un-ticking "Allow plain http" now actually revokes it

Pre-existing low-severity bug (found in the v1.4.4/v1.4.5 adversarial review; not
introduced by the v1.4.x webhook-source fixes). Un-ticking **"Allow plain http"**
in the license edit modal and saving did not clear `allow_http_webhook` — the flag
stayed `1`. An unchecked HTML checkbox is omitted from the POST, so the edit route
read the field as `None` ("preserve"), indistinguishable from "leave alone", and
the OFF direction was silently dropped. There was no way to revoke the flag from
the edit form without also changing the URL or rotating the secret.

The checkbox now ships a hidden `value="0"` companion, so an unchecked box still
posts an explicit OFF (a checked box's later `"1"` wins the last-value-wins form
parse), and the edit route maps the field to a plain True/False instead of None.
Turning the flag off on an `https://` row clears it; on an `http://` row it still
fails fast by design (you can't keep an http URL with http disabled). Pinned by
tests for the revoke-on-save behaviour and the hidden-companion wiring.

No schema change.

## v1.4.5 — rotating a secret no longer re-locks a self-registered webhook

Follow-up to v1.4.4 (caught in adversarial review). The v1.4.4 fix still passed
`source="admin"` whenever it touched the webhook config, so ticking **"Rotate
signing secret on save"** on a `self`-source license (URL unchanged) flipped it
to `admin` — the same data-integrity failure, just via the rotate path instead of
a plain save. After the flip `/v1/check` stops echoing the new secret, so the
client keeps verifying with the old one and every signed delivery fails.

`edit_license` now relabels to `admin` **only when the admin actually changed the
URL** (taking ownership); a pure rotate preserves the existing source while still
minting a fresh secret. Pinned by tests for rotate-on-self (stays `self`) and
rotate-on-admin (stays `admin`).

No schema change.

## v1.4.4 — license edit no longer re-locks a self-registered webhook; modal scrolls

Two admin-UI bug fixes found while activating raanana's webhook.

- **Edit stopped silently re-locking `self` webhooks to `admin`.** The license
  edit modal's form always carries the existing `webhook_url`, and
  `edit_license` re-applied it with `source="admin"` on *every* save — so a plain
  "Save Changes" (editing plan/features/etc.) relabeled a self-registered webhook
  as admin-source, which stops `/v1/check` from echoing the signing secret and
  re-locks the URL against self-registration. (This is what reverted raanana right
  after a Convert-to-self.) `edit_license` now only touches the webhook config
  when the URL actually changed or a rotate was explicitly requested; an unrelated
  edit leaves `webhook_url` / `webhook_secret` / `webhook_url_source` untouched. A
  bare http-opt-in toggle is applied without disturbing them.
- **The edit modal scrolls instead of clipping its buttons.** `.modal-card` had a
  `max-width` but no height cap, so a tall modal (webhook + secret-reveal sections
  expanded) overflowed the viewport with no scroll and the Save button became
  unreachable. It now caps at `100vh - 2em` and scrolls its overflow (fixes every
  `.modal-card` dialog).

No schema change.

## v1.4.3 — dead-channel health badge on the webhook-deliveries page

Completes the dead-channel visibility surfaces. The webhook-deliveries page lists
every license with a `webhook_url` under **Configured receivers** ("what would
fire if anything happened"), but rendered no health signal — a receiver with no
signing secret looked identical to a live one, even though `deliver_*`
short-circuits and nothing ever fires.

- **Configured receivers** now has a **Push** column with the same On / **No
  secret** badge as the product-detail list. Every row there has a URL, so it's
  two-state (live vs dead). Boolean condition only — the secret value is never
  emitted into the page.

No schema/API change. Pairs with v1.4.0 (product list + API) and v1.4.1 (edit
modal); same signal, third surface.

## v1.4.2 — stop broadcasting webhook signing secrets into page source

Security hardening. The admin product-detail page embedded a `#licenses-data`
JSON block that emitted every license's **raw `webhook_secret`** (the HMAC
signing key) — so a single view-source on that page exposed the signing secrets
of all licenses at once. That defeated the existing "reveal the secret once, on
set/rotate" design: the modal only *displayed* the secret for the flagged row,
but the value for every row was already sitting in the DOM.

- **`#licenses-data` now carries `has_webhook_secret` (boolean) for all rows**
  and the raw `webhook_secret` value **only for the single row the server
  flagged** via `?webhook_lid` / `?issued` (`reveal_lid`). Every other row gets
  `""`. The post-set/rotate one-time reveal is unchanged; bulk broadcast is gone.
- The modal's dead-channel warning toggle now keys on `has_webhook_secret`
  instead of the raw value.

No schema change, no API change (the list API was already boolean-only since
v1.4.0). Behaviour visible to operators is identical; the secret simply stops
leaking into the page for non-revealed rows.

## v1.4.1 — dead-channel warning in the license edit modal

Consistency follow-up to v1.4.0. The list's "No secret" badge tells operators to
"click Update", but the edit modal it sends them to showed no such signal. The
modal now renders an inline warning (reusing the `.error` style) in edit mode
when a license has a `webhook_url` but no `webhook_secret` — source-agnostic,
mirroring the list badge. Toggled client-side from the existing licenses-data
block (no new data exposed; the raw secret handling is unchanged).

## v1.4.0 — admin visibility for dead webhook push-channels

A license with a `webhook_url` set but no `webhook_secret` has a silently-dead
push channel: `webhooks.deliver_*` short-circuits on the missing secret, yet the
admin list rendered a green "On" — no hint that nothing was being delivered.

- **Admin product-detail list** — the Webhook column is now three-state, sorted
  by health: `—` (no URL) / `On` (URL + secret, live) / **`No secret`** warning
  (URL set, secret NULL — deliveries suppressed), with a tooltip pointing to the
  fix (open the license and click Update to mint a secret).
- **JSON API** — `GET /v1/admin/products/{slug}/licenses` items now carry a
  `has_webhook_secret` boolean so a monitor can detect dead channels
  programmatically. The raw signing secret is never exposed over the list API.

No schema change. Companion to the separate `/v1/check` secret auto-heal change
(PR #77): that fix stops NEW dead self-source channels from forming; this makes
any *pre-existing* dead channel — including admin-source ones the auto-heal
deliberately skips — visible. The two are independent; if both land, merge the
auto-heal first so the version sequence stays contiguous.

## v1.3.1 — auto-heal missing webhook secrets on /v1/check

Bug fix for dormant outbound webhooks. A `self`-source license that registered
its `webhook_url` on an LS build predating secret-minting (or had its secret
wiped) was permanently stuck with `webhook_secret = NULL`: the mint only ever
fired on a URL *change*, so `webhooks.deliver_*` short-circuited and `/v1/check`
returned no secret to the client. The instant push channel never came up.

- **Auto-heal in `app/services/check.py`:** on any `/v1/check`, a `self`-source
  license that carries a `webhook_url` but no secret now gets one minted —
  even when the URL is unchanged. Idempotent (no rotation on later checks);
  emits a `webhook:secret_backfilled` audit event once.
- **Admin-source unchanged:** admin-set URLs are still not auto-minted or
  echoed over `/v1/check` (their secret is managed out-of-band and shown once
  in the admin UI). Pinned by test. Widening that to instant-push admin
  receivers remains an open product decision.
- Affected clients (e.g. ASM tenants that self-registered before secrets
  existed) self-heal on their next heartbeat with no admin action.

## v1.3.0 — in-app backup/restore (local + S3, manual + scheduled)

Operator-facing backup layer (the raw VM→GCS snapshot from v0.11 stays as
infra-level disaster recovery underneath):

- **Archive format:** logical dump of every table (manifest + JSONL per
  table, tar.gz) — engine-agnostic in BOTH directions (SQLite ⇄ Postgres),
  stamped with `app_version` + `alembic_version`. Restore refuses schema
  mismatches instead of corrupting.
- **Encryption:** when `LICENSE_KEY_ENCRYPTION_KEY` is set, archives are
  Fernet-encrypted under an HKDF-derived backup key (domain-separated from
  the KEK). `.lsbak` = encrypted, `.tar.gz` = plaintext dev mode (UI warns).
- **Admin UI "Backups" page:** Back Up Now, download, per-row + bulk delete,
  restore from a stored archive or an uploaded file. Restore is full-replace,
  gated by typing `RESTORE LICENSE SERVER`, and ALWAYS writes a local
  `pre-restore_` safety snapshot first — a bad restore is one more restore
  from undone. Audit events `backup:created` / `backup:restored`.
- **Scheduled:** `python -m app.scripts.run_backup` (new daily systemd timer
  `yg-license-app-backup.timer` in the GCP deploy) + retention sweep:
  `BACKUP_RETENTION_COUNT` (default 14) / `BACKUP_RETENTION_DAYS`;
  pre-restore snapshots are never auto-pruned.
- **Destinations:** local `BACKUP_DIR` (VM: `/data/backups`) always; optional
  S3-compatible upload (`BACKUP_S3_*` env — AWS/R2/MinIO/GCS-interop via
  configurable endpoint, boto3 lazy-imported). S3 failure is best-effort:
  logged + surfaced, never kills the backup.
- New dependency: `boto3`.

## v1.2.0 — feature presets; LS back to 100% product-agnostic

v1.1.0 hardcoded two consumer-specific (ASM) feature keys into the generic
authoring surface. That coupling is removed and replaced with a generic
mechanism that gives the same typo-safety for ANY key, any product:

- **Feature presets** (new `feature_presets` table + `/admin/presets` page):
  key + value type (bool / number / string / json) + default value. Scope is
  **global** (offered on every product's licenses) or **per-product**.
  Per-row trash + bulk-select, create/edit modal. Audit events
  (`preset:created/updated/deleted`). Deleting a preset never touches
  licenses — it's an authoring template, not a live reference. Deleting a
  product cascades its presets.
- **Structured features editor** in the license modal ("Edit…" next to
  Features JSON): rows of key / type / value, add keys manually or insert
  from a preset (default value editable per license). Serializes back into
  the raw JSON input — the server keeps a single `features_json` code path
  and the raw input stays fully hand-editable.
- **Removed (breaking, shipped <1 day in v1.1.0):** `ai_api_included` /
  `ai_included_usd_cap` top-level fields on
  `POST /v1/admin/products/{slug}/licenses`, the hardcoded "AI included"
  modal controls, and all related service-layer semantics (explicit-false,
  cap validation). Unknown body fields are ignored; pass such keys inside
  `features` instead. LS attaches no semantics to any features key — that's
  the consuming app's job (e.g. ASM reads `ai_api_included` /
  `ai_included_usd_cap` from the JWT; add those as presets via the UI).
- Existing licenses and issued JWTs are unaffected (`features` was always
  the stored shape). Alembic migration `3f8b2c91d4ae` (additive only).

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
