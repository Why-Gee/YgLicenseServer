# YgLicenseServer — production readiness plan

Owner: Yaniv
Date: 2026-05-05
Repo: <https://github.com/Why-Gee/YgLicenseServer>
Local: `L:\Work\Programming\Licenses\LicenseServer`

## Context

This is a self-hostable, multi-product license server. Issues Ed25519-signed
JWT licenses to client apps (first one: Animal Shelter Manager). Each
"product" is a separately-licensed app; the server hosts as many products
as you want, each with its own keypair, key prefix, and Stripe webhook secret.

Originally extracted from `Why-Gee/AnimalShelterManager` during ASM phase 2
(commit `bbbd42d` on branch `yg/Licensing-1`).

## Current state (v0.2.0)

Working:
- Multi-product schema, per-product Ed25519 keypair, JWT signing.
- `/v1/check`, `/v1/products/{slug}/pubkey`.
- Admin JSON API: products + licenses + customers + revoke.
- Admin web UI: login, dashboard, products CRUD-(no-update), license issue/revoke, customers, events.
- Stripe webhook handler (per-product secret, invoice.paid + payment_failed + subscription.deleted).
- 9 tests passing, ruff clean.
- Dockerfile, SQLite default, Postgres-ready.

Not done — see phases below.

## Pre-flight decisions

Resolve before phase 1.

- [ ] **Hosting target.** Fly.io free / Oracle Always Free / Hetzner small VPS / other. Affects phase 1d deployment artifacts.
- [ ] **Domain for the license server.** e.g. `licenses.gorali.io` / subdomain of a marketing domain / `.fly.dev` default. Affects TLS + client `LICENSE_SERVER_URL` defaults.
- [ ] **Email transport.** Postmark / SendGrid / Resend / SMTP relay. Free tiers exist for all. Affects phase 1c.
- [ ] **Paddle vs Stripe vs both.** Stripe Israel is invite-only; Paddle works in IL out of the box. Affects phase 1c (current code is Stripe-only).
- [ ] **Tax invoice integration.** Greeninvoice / iCount / manual. Out of code scope but needed before charging.

## Phase 1 — pre-customer-1 (~2 days)

Goal: a real human can pay you, get a key by email, install the client, and you can revoke them when their card fails.

### 1a — Alembic migrations (~half day)

Currently `init_db()` calls `Base.metadata.create_all()`. Fine for fresh DBs;
breaks the moment you add a column to an existing prod DB.

1. `alembic init alembic` in repo root.
2. Configure `alembic/env.py` to import `app.models:Base.metadata`, read `DATABASE_URL` from env.
3. Generate baseline migration: `alembic revision --autogenerate -m "0001 initial schema"`.
4. Replace `init_db()` with `alembic upgrade head` in lifespan (or move to a `docker-entrypoint.sh` like ASM did).
5. Document: "every schema change → `alembic revision --autogenerate -m '...'` → review the generated migration before committing".

Deliverables: `alembic/`, updated `lifespan`, README section "Schema migrations".

### 1b — CI workflow (~half day)

Currently no `.github/workflows/` in this repo.

1. `.github/workflows/test.yml` — runs on PR + push to main: `ruff check`, `pytest`, build Docker image.
2. `.github/workflows/release.yml` — on git tag `v*.*.*`: build + push to `ghcr.io/why-gee/yg-license-server:vX.Y.Z`.
3. Branch protection on `main` requiring CI green.

Deliverables: 2 workflow files, tag scheme documented in README.

### 1c — Email-on-issue (~half day)

When a license is created (admin/issue or stripe webhook), customer should
get an email with their key + instructions.

1. Pick transport (see pre-flight). Recommend **Resend** — free 3k/mo, dead-simple API.
2. New `app/email.py` — single function `send_license_email(customer_email, license_key, product, install_runbook_url)`.
3. Wire into `api.py:admin_issue` and `stripe_webhook.py:_extend_or_create`.
4. Per-product email template would be nice; v1 a single template with `product.name` + key is enough.
5. Add `RESEND_API_KEY` (or whichever) env var. Skip silently if unset (dev mode).

Deliverables: `app/email.py`, env var documented, integration tests with mocked transport.

### 1d — One deployment target wired (~half day)

Pick one (decided in pre-flight) and ship deployment config. Options:

**Fly.io path:**
1. `fly.toml` at repo root.
2. `fly postgres create` for the DB.
3. `fly secrets set ADMIN_TOKEN=... SESSION_SECRET=... RESEND_API_KEY=...`.
4. `fly deploy` from CI on tag push.
5. Custom domain via `fly certs add licenses.yourdomain.com`.

**Oracle / Hetzner VPS path:**
1. `deploy/systemd/yg-license-server.service` unit file.
2. `deploy/Caddyfile` (Caddy auto-HTTPS).
3. `deploy/install.sh` — apt update, install Docker, pull image, write systemd unit + Caddyfile, start.
4. Document the manual steps in `docs/deploy/<target>.md`.

Deliverables: working deployment, `docs/deploy/<target>.md` runbook, smoke-test step in CI that hits `/health` post-deploy.

## Phase 2 — pre-scale (~1 day)

Goal: harden basics before customer count enters double digits.

### 2a — CSRF on admin forms (~2h)

Single-admin so it's a low-severity gap, but trivial to fix. Add a CSRF token via `itsdangerous` (already a dep), include in every form, validate on POST. `fastapi-csrf-protect` exists if you'd rather not roll it.

### 2b — Rate limiting (~2h)

`/v1/check` and `/admin/login` are the two surfaces. `slowapi` (FastAPI-friendly Limiter) — limit `/v1/check` to e.g. 60/min per IP, `/admin/login` to 5/min per IP.

### 2c — Update flows (~3h)

UI gaps that hurt right now:
- Edit product: name, description (slug + key_prefix should be immutable post-creation).
- Extend a license's `valid_until` (manual override outside Stripe flow).
- Edit a license's `features` JSON.
- Regenerate a product's keypair (with very loud confirmation — invalidates every existing license under that product).

JSON API + UI form for each.

### 2d — Backup script + retention (~2h)

`scripts/backup.sh` — `pg_dump` (or `sqlite3 .backup`) to `/backups/yg-license-$(date).sql`, prune to 30. Document the cron.
`scripts/restore.sh` — single-command restore from latest dump.

### 2e — Audit log of admin actions (~2h)

Extend `events` table with admin-action types: `admin:login`, `admin:product_created`, `admin:license_revoked`, etc. The actor is just "admin" until phase 3 multi-admin.

## Phase 3 — beyond MVP (deferred until justified)

Don't do speculatively. Pull each in when a real reason hits.

### 3a — Customer self-service portal

Customers log in (magic link to email), see their licenses, retrieve forgotten keys, download install bundle. Needed when "forgot my key" emails get annoying (~customer #20).

### 3b — Bulk operations

CSV import for customers, bulk-issue licenses, bulk-revoke. Needed when issuing >5 licenses/month manually.

### 3c — Multi-admin + token rotation

`admin_users` table, role + permission scopes. Login with email + password (or SSO). Audit who did what. Needed when you have a teammate, contractor, or VA helping with support.

### 3d — Metrics + tracing

`/metrics` Prometheus endpoint, request IDs, structured logs. Needed when you can't tell from logs alone what's slow / what failed.

### 3e — Push revocation to clients

WebSocket or long-polling so clients learn about revocation faster than the next daily check. Needed only if a customer's grace-period exposure ever causes real damage (probably never).

### 3f — Machine fingerprinting

Tie a license to specific hardware so the same key on a different machine fails outright. The current `install_id` is trust-based. Needed if license sharing becomes a real abuse vector.

### 3g — Paddle webhook handler

Mirror `stripe_webhook.py` for Paddle's event shape. Needed if Stripe Israel is denied/delayed and you go Paddle-primary.

### 3h — Per-product email templates

Customizable Subject/Body per product (since one server can license multiple unrelated apps with different tones). Needed when product #2 ships.

### 3i — In-app license-key delivery (alternative to email)

`/v1/admin/by-email/<email>` — admin endpoint to look up a customer's existing keys by email. Removes "forgot my key" tickets without building a full portal.

## Open questions

- Hosting target picked? (gates 1d)
- Email transport picked? (gates 1c)
- Stripe-only or Paddle-too? (gates 1c+3g)
- Domain for the server? (gates 1d TLS)
- Backup destination — same host / S3 / R2 / Backblaze? (gates 2d)
- Naming: `yg-license-server` (PyPI-style) vs `YgLicenseServer` (GitHub-style) for everywhere — currently mixed. Pick one and normalize?

## Resume instructions

1. Read this file.
2. `git -C L:\Work\Programming\Licenses\LicenseServer log --oneline -5` — confirm `be09b07` (rename) is HEAD.
3. Resolve open questions above (at minimum hosting + email transport).
4. Pick a starting subphase. Recommend **1a (alembic)** — small, no external decisions, unblocks every later schema change.
5. Open one PR per subphase. Keep them under ~300 LoC each.
6. After each phase, bump version: 1a-1d → v0.3.0, 2a-2e → v0.4.0, etc.
