# Deploy YgLicenseServer to GCP e2-micro free tier

Target: a single GCP `e2-micro` Compute Engine VM in `us-west1`/`us-central1`/`us-east1` (the always-free regions), fronted by Caddy with a Let's Encrypt cert for `yg-license-server.duckdns.org` (free DDNS, transferable to a real domain later).

Cost: $0/month within the free tier limits (1 e2-micro VM + 30 GB standard disk + 1 GB egress/mo + 1 static IP while attached to a running VM).

Prereqs (one-time, manual):
1. A Google account with billing enabled (CC required to create the project; stays at $0 if you stay in free tier).
2. A DuckDNS account — sign up at [duckdns.org](https://www.duckdns.org/) using GitHub/Google/etc., claim the subdomain `yg-license-server`, copy the token from your dashboard.
3. A Resend account (only needed when you want to actually send emails; license issuance works without it).

## 1. Create the GCP VM

Use either the [gcloud CLI](https://cloud.google.com/sdk/docs/install) or the Console UI. CLI is faster:

```sh
# Pick a project; create it if you don't have one yet
PROJECT=yg-license-prod
gcloud projects create $PROJECT
gcloud config set project $PROJECT
gcloud services enable compute.googleapis.com

# Reserve a static IP (free while in use)
gcloud compute addresses create yg-license-server-ip --region=us-west1
STATIC_IP=$(gcloud compute addresses describe yg-license-server-ip --region=us-west1 --format='value(address)')
echo "Static IP: $STATIC_IP"

# Create the VM (e2-micro, Debian 12, free-tier region)
gcloud compute instances create yg-license-server \
  --zone=us-west1-a \
  --machine-type=e2-micro \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --boot-disk-size=30GB --boot-disk-type=pd-standard \
  --address=$STATIC_IP \
  --tags=http-server,https-server

# Open 80/443
gcloud compute firewall-rules create allow-http  --allow tcp:80  --target-tags=http-server  --source-ranges=0.0.0.0/0
gcloud compute firewall-rules create allow-https --allow tcp:443 --target-tags=https-server --source-ranges=0.0.0.0/0
```

Verify the VM is up:

```sh
gcloud compute instances list
# Expect STATUS=RUNNING for yg-license-server
```

## 2. Point DuckDNS at the static IP

In your [DuckDNS dashboard](https://www.duckdns.org/), set the `current ip` for `yg-license-server` to the value of `$STATIC_IP` from the previous step. Or use curl:

```sh
TOKEN=<your-duckdns-token>
curl -sS "https://www.duckdns.org/update?domains=yg-license-server&token=$TOKEN&ip=$STATIC_IP"
# Expect "OK"
```

Verify DNS:

```sh
dig +short yg-license-server.duckdns.org
# Expect the static IP
```

DNS propagation is typically <1 minute since DuckDNS uses a low TTL.

## 3. SSH in and prepare config files

```sh
gcloud compute ssh yg-license-server --zone=us-west1-a
# (now on the VM)
```

Clone the repo (read-only is fine — you only need the deploy/ tree):

```sh
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/Why-Gee/YgLicenseServer.git
cd YgLicenseServer
```

Create the env files (these never leave the VM):

```sh
sudo mkdir -p /etc/yg-license-server
sudo cp deploy/gcp/yg-license-server.env.example /etc/yg-license-server/yg-license-server.env

# Generate two distinct random tokens
ADMIN_TOKEN=$(python3 -c "import secrets;print(secrets.token_urlsafe(32))")
SESSION_SECRET=$(python3 -c "import secrets;print(secrets.token_urlsafe(32))")

sudo tee /etc/yg-license-server/yg-license-server.env >/dev/null <<EOF
ADMIN_TOKEN=$ADMIN_TOKEN
SESSION_SECRET=$SESSION_SECRET
DATABASE_URL=sqlite:////data/license.db
COOKIE_SECURE=true
RESEND_API_KEY=
EMAIL_FROM=onboarding@resend.dev
EOF

sudo tee /etc/yg-license-server/duckdns.env >/dev/null <<EOF
DUCKDNS_DOMAIN=yg-license-server
DUCKDNS_TOKEN=<paste-your-token>
EOF

sudo chmod 600 /etc/yg-license-server/*.env
```

**Save the `ADMIN_TOKEN` value** — you'll need it for the admin UI login and admin API calls.

## 4. Run the install script

```sh
sudo IMAGE=ghcr.io/why-gee/yg-license-server:latest \
     LICENSE_HOST=yg-license-server.duckdns.org \
     ADMIN_EMAIL=<your-email-for-letsencrypt> \
     ./deploy/gcp/install.sh
```

This will:
1. `apt install` Docker + Caddy if missing.
2. Pull the latest image from ghcr.io.
3. Write `/etc/caddy/Caddyfile` with your hostname and start Caddy (which will request a Let's Encrypt cert on first inbound HTTPS hit — usually <30 sec).
4. Install the `yg-license-server.service` + `duckdns-update.timer` systemd units.
5. Start everything and curl `/health` locally.

## 5. Smoke-test from outside

```sh
# from your laptop, NOT the VM
curl -sS https://yg-license-server.duckdns.org/health
# Expect: {"ok":true,"version":"0.3.0-dev"}

# admin token works
curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://yg-license-server.duckdns.org/v1/admin/products
# Expect: []
```

Open `https://yg-license-server.duckdns.org/admin` in your browser, log in with the `ADMIN_TOKEN`, create your first product.

## 6. Updating to a new release

After CI publishes a new tag (`git tag v0.3.0 && git push --tags`):

```sh
gcloud compute ssh yg-license-server --zone=us-west1-a -- \
  'sudo systemctl restart yg-license-server.service'
```

The systemd unit's `ExecStartPre=docker pull ${IMAGE}` will fetch `:latest` (or whatever you set `IMAGE` to in the unit) and replace the running container.

To pin a specific version, edit `/etc/systemd/system/yg-license-server.service` to set `IMAGE=ghcr.io/why-gee/yg-license-server:v0.3.0`, `daemon-reload`, restart.

## 7. Backups (automated to GCS)

`install.sh` wires up a nightly `sqlite3 .backup` → gzip → `gs://yglicenseserver-backups/license.db.gz` pipeline. Bucket has object versioning enabled; lifecycle policy deletes versions older than 30 days. Net effect: ~30 daily snapshots retained automatically.

Pieces installed by `install.sh`:
- `/usr/local/bin/yg-license-backup.sh` — the script (uses python3's stdlib sqlite3, no extra apt install)
- `/etc/systemd/system/yg-license-backup.service` — oneshot unit
- `/etc/systemd/system/yg-license-backup.timer` — daily at 03:17 UTC with ±10min jitter
- IAM binding: `roles/storage.objectAdmin` on the bucket for the VM's default service account (bucket-scoped, not project-wide)

Smoke-test after install:

```sh
sudo systemctl start yg-license-backup.service
journalctl -u yg-license-backup.service -n 50
gsutil ls -l gs://yglicenseserver-backups/
# Expect one fresh object license.db.gz; metadata header carries snapshot timestamp.
```

### Restore from backup

```sh
# 1. Pick the version. `gsutil ls -a` shows all versions including generations.
gsutil ls -a gs://yglicenseserver-backups/license.db.gz
# Each line ends with #<generation>; pick the one you want.

# 2. Download + decompress to a staging path.
gsutil cp 'gs://yglicenseserver-backups/license.db.gz#<generation>' /tmp/restore.db.gz
gunzip /tmp/restore.db.gz   # produces /tmp/restore.db

# 3. Stop the server, replace the live DB, fix ownership, restart.
sudo systemctl stop yg-license-server.service
sudo cp /var/lib/yg-license-server/license.db /var/lib/yg-license-server/license.db.bak
sudo cp /tmp/restore.db /var/lib/yg-license-server/license.db
sudo chown 10001:10001 /var/lib/yg-license-server/license.db
sudo systemctl start yg-license-server.service
curl -fsS http://127.0.0.1:8800/readyz
```

Losing this file means losing every product's private key — every license stops verifying. Keep the bucket alive.

## Switching to your own domain later

When you buy a real domain (e.g. `gorali.io`):

1. In your domain's DNS host (e.g. Cloudflare), add `A licenses.gorali.io → <STATIC_IP>`.
2. SSH in and edit `/etc/caddy/Caddyfile` — duplicate the `yg-license-server.duckdns.org` block so both hostnames serve the same backend:
   ```
   yg-license-server.duckdns.org, licenses.gorali.io {
       encode zstd gzip
       reverse_proxy 127.0.0.1:8800
       ...
   }
   ```
3. `sudo systemctl reload caddy` — Caddy gets a Let's Encrypt cert for the new hostname automatically.
4. Push a client release with `LICENSE_SERVER_URL=https://licenses.gorali.io`.
5. After all clients have rolled forward, drop `yg-license-server.duckdns.org` from the Caddyfile and reload.

No DB migration, no key rotation, no customer impact.

## Troubleshooting

- **`/health` returns 502** — `systemctl status yg-license-server.service`, `journalctl -u yg-license-server.service -n 100`. Most common: env file syntax error or wrong `DATABASE_URL`.
- **TLS errors / cert not issued** — `journalctl -u caddy -n 100`. Most common causes: port 80 blocked (check firewall rule `allow-http`), DNS hasn't propagated yet, or `ADMIN_EMAIL` invalid in `/etc/caddy/Caddyfile`.
- **DuckDNS shows wrong IP** — `systemctl start duckdns-update.service` to force a refresh; check `journalctl -u duckdns-update.service`.
- **Container can't reach internet for `pip install`** — only happens on first `docker pull` if there's a transient ghcr.io issue; retry.
- **Out of disk** — `docker system prune -a` to remove old images. The DB itself is tiny (MB even at 10k licenses).
