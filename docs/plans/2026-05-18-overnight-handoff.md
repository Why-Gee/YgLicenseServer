# Overnight handoff — v0.11.2 → v0.14.0

**Date:** 2026-05-18 (Yaniv local timezone, started ~01:30, finished ~03:30)
**Branch:** `main` (everything merged, ready to deploy)
**Current version:** 0.14.0
**Tests:** 160 passing, ruff clean

## TL;DR

Four PRs landed overnight, no prod deploys yet. Wake up, run `./deploy.ps1`, then re-run `install.sh` on the VM to wire the new systemd units. ~5 min total.

| Version | PR | What it ships |
|--|--|--|
| v0.11.2 | [#46](https://github.com/Why-Gee/YgLicenseServer/pull/46) | T2-A events pruning + T2-B JSON logs |
| v0.12.0 | [#47](https://github.com/Why-Gee/YgLicenseServer/pull/47) | Webhook retry queue (durable at-least-once) |
| v0.13.0 | [#48](https://github.com/Why-Gee/YgLicenseServer/pull/48) | License-expiry email warnings |
| v0.14.0 | [#49](https://github.com/Why-Gee/YgLicenseServer/pull/49) | CSV exports + admin table filter |

## What's still queued (explicitly NOT done)

From the v0.11 plan's Tier-3:
- **Postgres migration path** — needs a running Postgres instance for end-to-end testing; not something to ship blind.
- **Stripe events via background worker** — explicitly deferred ("until volume justifies") in the v0.11 plan's locked decisions.

Both stay in Tier-3 until you decide they're warranted.

## v0.11.2 -- events pruning + JSON logs

**T2-A**: `python -m app.scripts.prune_events [--older-than-days 90] [--types heartbeat]`
- Deletes only `heartbeat` events older than N days by default.
- Never touches audit-relevant types (issued, status:*, license:*, customer:*, webhook:*).
- Weekly systemd timer at Sun 04:11 UTC (offset from the nightly backup).
- `--dry-run` reports the count without deleting.

**T2-B**: structured JSON logs behind `LOG_FORMAT=json`.
- New `app/log_format.py` with `JsonFormatter` (time, level, logger, message, request_id, exc_info).
- Default stays text so dev output is unchanged. Set `LOG_FORMAT=json` in `.env.prod` to flip prod over.

## v0.12.0 -- webhook retry queue

**The biggest customer-impact item.** Outbound license webhooks were best-effort sync; a receiver outage silently dropped events. Now they're durable at-least-once.

**Flow:**
1. Service-layer functions (set_status, edit_license, _delete_license_in_tx) call `wh.enqueue(db, ...)` BEFORE `db.commit()`. Queue insert is atomic with the state change.
2. After commit, `_run(...)` schedules `wh.attempt_in_fresh_session(delivery_id)`. On 2xx → `delivered`; on any failure → `pending` with bumped `next_attempt_at`.
3. Backoff: 1min, 5min, 30min, 2h, 12h, 24h → abandon after 7 attempts.
4. systemd timer `yg-license-retry-webhooks.timer` runs `python -m app.scripts.retry_webhooks` every 5 minutes.

**Receiver dedup**: `WebhookDelivery.id` doubles as `X-License-Server-Event-Id` across retries — idempotent receivers see one logical event.

**Schema**: new table `webhook_deliveries`, Alembic migration `4a247674ec5e` descending from `8a336b18bca1`.

**Out of scope**: admin UI page to inspect pending/abandoned deliveries. Use `journalctl -u yg-license-retry-webhooks.service` or query the table directly until you decide that page is worth building.

## v0.13.0 -- license-expiry warnings

`python -m app.scripts.send_expiry_warnings` emails customers at three thresholds before their license lapses:
- **30 days out** — early heads-up
- **14 days out** — mid-warning
- **7 days out** — renew-now urgency

**Idempotency**: each successful send records an `expiry_warning:<N>` event. Re-running the script doesn't re-send at the same threshold; a license that progresses 30d → 14d does get the new warning.

Daily systemd timer at 09:23 UTC ±15min. Graceful no-op when `RESEND_API_KEY` is unset (so dev/staging don't crash-loop).

## v0.14.0 -- CSV exports + admin filter

**Three CSV endpoints** (admin-bearer-gated, streamed):
- `GET /v1/admin/exports/customers.csv`
- `GET /v1/admin/exports/products/<slug>/licenses.csv`
- `GET /v1/admin/exports/products/<slug>/events.csv`

Streamed via `yield_per(500)` so a 10k-row table doesn't buffer. RFC-4180 quoting. Customers + Licenses pages get an inline `CSV` link in the toolbar.

**Client-side row filter** on Customers, per-product Licenses, Events. Tiny `<input>` widget driven by `data-filter-target="#table"`; filters by case-insensitive substring against full row textContent. Coexists with the existing `data-sortable` JS. No backend change — for cross-page search, use the CSV exports.

## How to deploy this in the morning

**Recommended path** — one deploy that picks up all four versions at once:

```powershell
# From the laptop, on main:
./deploy.ps1
```

`deploy.ps1` will:
1. Detect that `app/__init__.py` is at 0.14.0 and tag `v0.14.0`.
2. Push the tag; CI builds and pushes `ghcr.io/why-gee/yg-license-server:v0.14.0`.
3. Push your current `.env.prod` to the VM.
4. `systemctl restart yg-license-server.service`, which pulls the new image.
5. Verify `/health` reports 0.14.0.

**Then** SSH to the VM and re-run `install.sh` to wire the three new systemd units (prune-events, retry-webhooks, expiry-warnings):

```bash
# From the laptop:
gcloud compute ssh yg-license-server --zone=us-west1-a --command='mkdir -p /tmp/v0.14-deploy'
gcloud compute scp --zone=us-west1-a --recurse deploy/gcp yg-license-server:/tmp/v0.14-deploy/
gcloud compute ssh yg-license-server --zone=us-west1-a --command='chmod +x /tmp/v0.14-deploy/gcp/*.sh && sudo IMAGE=ghcr.io/why-gee/yg-license-server:latest LICENSE_HOST=yg-license-server.duckdns.org ADMIN_EMAIL=yanivg@gmail.com /tmp/v0.14-deploy/gcp/install.sh'
```

The script is idempotent; it'll skip the GCS admin steps (we did them from the laptop in v0.11.0) and just install the new units.

### Smoke tests (5 min total)

```bash
# 1. JSON logs (optional -- set LOG_FORMAT=json in .env.prod first if you want)
curl -sS https://yg-license-server.duckdns.org/healthz

# 2. CSV export
curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://yg-license-server.duckdns.org/v1/admin/exports/customers.csv | head -5

# 3. New systemd timers are armed
gcloud compute ssh yg-license-server --zone=us-west1-a --command='systemctl list-timers | grep yg-license'
# Expect 4 timers: backup, prune-events, retry-webhooks, expiry-warnings

# 4. Webhook retry-queue table exists (Alembic ran on startup)
gcloud compute ssh yg-license-server --zone=us-west1-a --command="docker exec \$(docker ps -q -f name=yg-license-server) python -c 'from app.db import SessionLocal; from app.models import WebhookDelivery; s=SessionLocal(); print(s.query(WebhookDelivery).count(), \"pending deliveries\")'"

# 5. Trigger prune-events manually (should report 0 to delete since heartbeats are <2 days old)
gcloud compute ssh yg-license-server --zone=us-west1-a --command='sudo systemctl start yg-license-prune-events.service && sudo journalctl -u yg-license-prune-events.service -n 10 --no-pager'

# 6. Admin UI -- log in, /admin/customers, type into the filter, confirm rows hide/show.
#    /admin/products/asm -- same filter on the licenses table.
```

### If anything goes sideways

- **`alembic upgrade head` fails on startup**: there's only one new migration this round (`4a247674ec5e_webhook_deliveries`). Check `journalctl -u yg-license-server.service` for the SQL error.
- **Webhook deliveries pile up in `pending`**: query the table to see `last_error`. The retry worker logs each attempt in `journalctl -u yg-license-retry-webhooks.service`. ASM is the only consumer and their webhook URL is stable, so this is unlikely.
- **Expiry warnings spam**: only fires when `RESEND_API_KEY` is set and a real license is within 30 days of expiry. The dedup events guard against re-spamming. If you see duplicates, that's a bug worth flagging.

## Notes / followups worth considering

- **CI build time**: each PR triggered a ~1min CI run + a ~3.5min release build on tag push. The four-tag sequence will rebuild four images; deploying just `:latest` after v0.14 catches everything.
- **install.sh has accumulated five systemd units** (server, backup, prune-events, retry-webhooks, expiry-warnings) + duckdns. Might be worth a `deploy/gcp/units/` subdirectory before v1.0 to keep the file count down.
- **Webhook retry observability**: I deliberately didn't build an admin UI page for `webhook_deliveries`. If ASM ever has a webhook-receiver outage, you'll appreciate one. A simple read-only table at `/admin/webhook-deliveries` is maybe 30 lines of code. Note for v0.15 if it bites.

🤖 Generated overnight by Claude Opus 4.7 (1M context)
