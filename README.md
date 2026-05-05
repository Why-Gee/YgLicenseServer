# YgLicenseServer

[![test](https://github.com/Why-Gee/YgLicenseServer/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/Why-Gee/YgLicenseServer/actions/workflows/test.yml)

Self-hostable multi-product license server. Issues Ed25519-signed JWTs to
on-prem app installs, handles Stripe/Paddle webhooks, ships with a web
admin UI for issuing keys, revoking, and downloading public keys.

Originally extracted from [Animal Shelter Manager](https://github.com/Why-Gee/AnimalShelterManager) — generic enough to license any app you build.

## Concepts

- **Product** — a separately-licensed app (e.g. `asm`, `app2`). Each product gets its own Ed25519 keypair, key prefix, and (optional) Stripe webhook secret. The public key is baked into the client app's image; the private key never leaves this server.
- **Customer** — an email + optional Stripe customer ID. Customers can hold licenses across multiple products.
- **License** — a key (`asm_…`) bound to one customer + one product. Carries `plan`, `max_users`, `features` (free-form JSON), `valid_until`, `status` (active / delinquent / revoked).
- **Install** — a heartbeat row updated each time a client calls `/v1/check`. Stable per-host via the client's machine-id.

## Quick start

```sh
python -m venv .venv && source .venv/bin/activate         # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"

# generate a long random admin token (used as both auth + session-cookie key)
export ADMIN_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
export SESSION_SECRET=$ADMIN_TOKEN
export DATABASE_URL=sqlite:///./license.db
export COOKIE_SECURE=false                                # local http only

uvicorn app.main:app --reload --port 8800
```

Open <http://localhost:8800/admin>, log in with `$ADMIN_TOKEN`, and create your first product.

## Deploying

Any host that runs Docker. The included `Dockerfile` is single-stage, ~120MB.

```sh
docker build -t yg-license-server .
docker run --rm -p 8800:8800 \
  -e ADMIN_TOKEN=$ADMIN_TOKEN \
  -e SESSION_SECRET=$ADMIN_TOKEN \
  -e DATABASE_URL=sqlite:////data/license.db \
  -e COOKIE_SECURE=true \
  -v $PWD/data:/data \
  yg-license-server
```

For prod use Postgres (`postgresql+psycopg://...`), put the server behind HTTPS, and **back up the DB regularly** — losing it loses every license you've ever issued (the private keys live there).

## API surface

### Public

- `POST /v1/check { key, install_id, version }` → `{ jwt, valid_until, features, max_users, license_id, product }`
- `GET  /v1/products/{slug}/pubkey` → product's public key as PEM (no auth — public keys aren't secret)

### Admin (Bearer ADMIN_TOKEN)

- `POST /v1/admin/products` — create product (auto-generates keypair)
- `GET  /v1/admin/products` — list
- `GET  /v1/admin/products/{slug}` — details (includes pub key)
- `POST /v1/admin/products/{slug}/licenses` — issue license
- `GET  /v1/admin/products/{slug}/licenses` — list product's licenses
- `POST /v1/admin/licenses/{id}/revoke`
- `GET  /v1/admin/customers`

### Webhooks (per-product)

- `POST /v1/products/{slug}/stripe-webhook` — Stripe events → license state. Each product has its own webhook secret.

## Client integration

In the client app, embed the product's public key and verify the JWT cached on disk. Reference implementation in ASM: <https://github.com/Why-Gee/AnimalShelterManager/tree/main/backend/app/licensing>.

Minimal client check (Python, pyjwt):

```python
import jwt
claims = jwt.decode(token, public_key_pem, algorithms=["EdDSA"], options={"verify_exp": False})
# claims has: license_id, install_id, plan, max_users, features, valid_until, product
```

`valid_until` is the source of truth for license expiry; `exp` is just the JWT cache TTL (default 7 days). Clients honor a configurable grace period after `valid_until` so the server can be down briefly without breaking customers.

## License-issue email

When a license is created (admin UI, `/v1/admin/.../licenses`, or Stripe `invoice.paid`), the customer is emailed their key via [Resend](https://resend.com/). Email sends are best-effort — a transient outage won't fail license issuance.

Config:

```sh
export RESEND_API_KEY=re_...                # required for actual sends
export EMAIL_FROM="onboarding@resend.dev"   # default; replace with licenses@<your-domain> after verifying a domain in Resend
```

If `RESEND_API_KEY` is unset, sends are no-ops and the intent is logged. That's the supported "dev / not-yet-launched" mode — useful while you wire up Stripe / a domain.

To go live to real customers:

1. Sign up at [resend.com](https://resend.com), grab an API key.
2. Add a sending domain (4 DNS records — DKIM/SPF/MX/return-path). Resend's onboarding walks you through it.
3. Set `EMAIL_FROM=licenses@<your-verified-domain>` and redeploy.

Until then, the test sender `onboarding@resend.dev` only delivers to the email you signed up for at Resend.

## Schema migrations

This repo uses [Alembic](https://alembic.sqlalchemy.org/) for schema changes. The Docker image runs `alembic upgrade head` on container boot via `docker-entrypoint.sh`, so prod DBs are migrated automatically.

After any change to `app/models.py`:

```sh
alembic revision --autogenerate -m "<short message>"
# review the generated file under alembic/versions/ before committing
# autogenerate misses renames + enum changes — hand-edit those
```

Local apply / rollback:

```sh
alembic upgrade head        # apply pending
alembic downgrade -1        # roll back one — local only, never on prod
alembic history             # see chain
```

Tests bypass alembic and call `db.init_db()` to set up an in-memory SQLite — fast, no migration step in the unit-test path.

## Versioning & releases

SemVer. `app/__init__.py:__version__` is the source of truth — bump it together with `pyproject.toml:version` in the same commit.

CI publishes a Docker image to GitHub Container Registry on every `v*.*.*` tag:

```sh
# bump version, commit, then:
git tag v0.3.0
git push --tags
# release.yml builds + pushes ghcr.io/why-gee/yg-license-server:v0.3.0 + :latest
docker pull ghcr.io/why-gee/yg-license-server:v0.3.0
```

Branch protection on `main` (one-time setup in GitHub: *Settings → Branches → Add rule*) — require the `test` workflow green before merging.

## Backups (do not skip)

The DB holds every product's private key. Lose it and every license stops verifying.

```sh
# daily cron
sqlite3 /data/license.db ".backup '/backups/license-$(date -u +%F).db'"
# or for postgres
pg_dump $DATABASE_URL > /backups/license-$(date -u +%F).sql
```

Keep at least one off-host copy.
