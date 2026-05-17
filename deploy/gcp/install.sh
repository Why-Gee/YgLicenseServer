#!/bin/bash
# Bootstrap a Debian 12 GCP VM into a YgLicenseServer host.
# Run as root (or via sudo) after SSHing in. Idempotent: re-running upgrades
# Caddy/Docker if needed and restarts the service with whatever's in env files.
#
# Pre-reqs (do these BEFORE running this script):
#   1. /etc/yg-license-server/yg-license-server.env (copy from .env.example, fill in)
#   2. /etc/yg-license-server/duckdns.env (DUCKDNS_DOMAIN + DUCKDNS_TOKEN)
#   3. The IMAGE env var must be set (or pass as arg).
#
# Usage:
#   sudo IMAGE=ghcr.io/why-gee/yg-license-server:latest ./install.sh
#   sudo LICENSE_HOST=yg-license-server.duckdns.org ADMIN_EMAIL=you@example.com IMAGE=... ./install.sh

set -euo pipefail

[ "$(id -u)" = "0" ] || { echo "must run as root (use sudo)" >&2; exit 1; }

IMAGE="${IMAGE:-ghcr.io/why-gee/yg-license-server:latest}"
LICENSE_HOST="${LICENSE_HOST:-yg-license-server.duckdns.org}"
ADMIN_EMAIL="${ADMIN_EMAIL:-}"
GCP_PROJECT="${GCP_PROJECT:-yglicenseserver}"
GCP_REGION="${GCP_REGION:-us-west1}"
BACKUP_BUCKET="${BACKUP_BUCKET:-yglicenseserver-backups}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
[ -n "$ADMIN_EMAIL" ] || { echo "ADMIN_EMAIL env var required (Let's Encrypt account)" >&2; exit 1; }

ENV_DIR=/etc/yg-license-server
DATA_DIR=/var/lib/yg-license-server
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> apt update + base packages"
apt-get update -y
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg debian-archive-keyring apt-transport-https

# Docker
if ! command -v docker >/dev/null; then
  echo "==> install Docker"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/debian $VERSION_CODENAME stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io
  systemctl enable --now docker
fi

# Caddy
if ! command -v caddy >/dev/null; then
  echo "==> install Caddy"
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y
  apt-get install -y caddy
fi

echo "==> directories"
install -d -m 0755 "$ENV_DIR"
install -d -m 0755 "$DATA_DIR"
install -d -m 0755 /var/log/caddy

# The container runs as the non-root `app` user (uid 10001 -- see Dockerfile).
# The bind-mounted $DATA_DIR has to be writable by that uid or SQLite raises
# "attempt to write a readonly database" and the entrypoint's `alembic upgrade
# head` crash-loops the unit. chown is idempotent; safe on re-run.
chown -R 10001:10001 "$DATA_DIR"

[ -f "$ENV_DIR/yg-license-server.env" ] || {
  echo "ERROR: $ENV_DIR/yg-license-server.env missing." >&2
  echo "Copy deploy/gcp/yg-license-server.env.example there and fill in." >&2
  exit 1
}
[ -f "$ENV_DIR/duckdns.env" ] || {
  echo "ERROR: $ENV_DIR/duckdns.env missing." >&2
  echo "Create with:" >&2
  echo "  DUCKDNS_DOMAIN=<subdomain-without-.duckdns.org>" >&2
  echo "  DUCKDNS_TOKEN=<token-from-duckdns.org>" >&2
  exit 1
}
chmod 600 "$ENV_DIR"/*.env

echo "==> install Caddyfile"
LICENSE_HOST="$LICENSE_HOST" ADMIN_EMAIL="$ADMIN_EMAIL" \
  envsubst '${LICENSE_HOST} ${ADMIN_EMAIL}' \
  < "$SCRIPT_DIR/Caddyfile" > /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile
systemctl restart caddy

echo "==> install license-server systemd unit"
# Copy the unit verbatim -- ${IMAGE} stays as a systemd placeholder and is
# resolved at runtime from the env file. That way `deploy.ps1` can push a
# new tag + `systemctl restart` will docker-pull it without re-running
# install.sh or editing the unit on disk.
install -m 0644 "$SCRIPT_DIR/yg-license-server.service" /etc/systemd/system/yg-license-server.service

# Make sure IMAGE is in the env file (since the unit reads it from there).
# Idempotent: if IMAGE is already set, leave it alone.
if ! grep -q '^IMAGE=' "$ENV_DIR/yg-license-server.env"; then
  echo "IMAGE=$IMAGE" >> "$ENV_DIR/yg-license-server.env"
  echo "    added IMAGE=$IMAGE to $ENV_DIR/yg-license-server.env"
fi

echo "==> install duckdns updater"
install -m 0755 "$SCRIPT_DIR/duckdns-update.sh" /usr/local/bin/duckdns-update.sh
install -m 0644 "$SCRIPT_DIR/duckdns-update.service" /etc/systemd/system/duckdns-update.service
install -m 0644 "$SCRIPT_DIR/duckdns-update.timer"   /etc/systemd/system/duckdns-update.timer

echo "==> GCS backup bucket + lifecycle"
# gcloud / gsutil come pre-installed on GCE Debian images. If they're not on
# PATH (custom image), bail loudly -- we'd rather refuse to set up backups
# than silently skip them.
command -v gcloud >/dev/null || { echo "ERROR: gcloud not on PATH; cannot configure backups" >&2; exit 1; }
command -v gsutil >/dev/null || { echo "ERROR: gsutil not on PATH; cannot configure backups" >&2; exit 1; }

# Idempotent: `gsutil ls -b` exits non-zero when the bucket doesn't exist.
if ! gsutil -q ls -b "gs://${BACKUP_BUCKET}" >/dev/null 2>&1; then
  echo "    creating gs://${BACKUP_BUCKET} in ${GCP_REGION}"
  gcloud storage buckets create "gs://${BACKUP_BUCKET}" \
    --project="${GCP_PROJECT}" \
    --location="${GCP_REGION}" \
    --default-storage-class=STANDARD \
    --uniform-bucket-level-access
else
  echo "    gs://${BACKUP_BUCKET} already exists"
fi

# Versioning gives us "30 daily snapshots" semantics with one stable object
# name, so the backup script doesn't need to think about per-day naming.
gcloud storage buckets update "gs://${BACKUP_BUCKET}" --versioning

# Lifecycle policy: delete non-current (versioned) objects older than N days.
LIFECYCLE_JSON="$(mktemp)"
cat > "$LIFECYCLE_JSON" <<JSON
{
  "lifecycle": {
    "rule": [
      {
        "action": {"type": "Delete"},
        "condition": {"age": ${BACKUP_RETENTION_DAYS}, "isLive": false}
      },
      {
        "action": {"type": "Delete"},
        "condition": {"numNewerVersions": ${BACKUP_RETENTION_DAYS}}
      }
    ]
  }
}
JSON
gcloud storage buckets update "gs://${BACKUP_BUCKET}" --lifecycle-file="$LIFECYCLE_JSON"
rm -f "$LIFECYCLE_JSON"

# Grant the VM's default service account write access to the bucket only
# (not project-wide). Re-running is idempotent: gcloud add-iam-policy-binding
# is a no-op when the binding already exists.
VM_SA="$(curl -sS -H 'Metadata-Flavor: Google' \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email || true)"
if [ -n "$VM_SA" ]; then
  echo "    granting roles/storage.objectAdmin on bucket to ${VM_SA}"
  gcloud storage buckets add-iam-policy-binding "gs://${BACKUP_BUCKET}" \
    --member="serviceAccount:${VM_SA}" \
    --role="roles/storage.objectAdmin" >/dev/null
else
  echo "    WARN: could not read VM service account from metadata; skipping IAM grant"
fi

echo "==> install backup script + systemd units"
install -m 0755 "$SCRIPT_DIR/backup.sh" /usr/local/bin/yg-license-backup.sh
install -m 0644 "$SCRIPT_DIR/yg-license-backup.service" /etc/systemd/system/yg-license-backup.service
install -m 0644 "$SCRIPT_DIR/yg-license-backup.timer"   /etc/systemd/system/yg-license-backup.timer

# Surface the bucket name in the env file so backup.sh + future ops scripts
# read the same value. Idempotent guard.
if ! grep -q '^BACKUP_BUCKET=' "$ENV_DIR/yg-license-server.env"; then
  echo "BACKUP_BUCKET=$BACKUP_BUCKET" >> "$ENV_DIR/yg-license-server.env"
fi

echo "==> systemctl daemon-reload + enable + start"
systemctl daemon-reload
systemctl enable --now duckdns-update.timer
systemctl start duckdns-update.service  # one-shot kick to register IP immediately
systemctl enable --now yg-license-server.service
systemctl enable --now yg-license-backup.timer

echo
echo "==> wait for service health"
for i in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS http://127.0.0.1:8800/health >/dev/null; then
    echo "    /health OK after ${i}s"
    break
  fi
  sleep 2
done

echo
echo "DONE. Smoke-test from anywhere with:"
echo "  curl -sS https://${LICENSE_HOST}/health"
echo
echo "Caddy will obtain a Let's Encrypt cert on first request — give it ~30s."
