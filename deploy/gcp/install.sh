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

# Append a `KEY=VALUE` line to the env file IFF the key isn't already set.
# Guarantees the file ends with a newline first (deploy.ps1's scp-then-tee
# flow can leave the final line without one; without this guard a plain
# `echo >>` glues the new key onto the previous value -- which corrupted
# LICENSE_KEY_ENCRYPTION_KEY in v0.11.0). Idempotent.
ensure_env_line() {
  local key="$1" val="$2" file="$ENV_DIR/yg-license-server.env"
  grep -q "^${key}=" "$file" && return 0
  # If file is non-empty and doesn't end with a newline, add one before
  # appending. `tail -c1` is the cheapest "what's the last byte?" probe.
  if [ -s "$file" ] && [ "$(tail -c1 "$file" | wc -l)" -eq 0 ]; then
    echo "" >> "$file"
  fi
  echo "${key}=${val}" >> "$file"
  echo "    added ${key}=${val} to $file"
}

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
ensure_env_line "IMAGE" "$IMAGE"

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

# Bucket lifecycle: create + versioning + lifecycle + IAM are all
# admin-level ops. On a GCE VM whose default service account only has
# `devstorage.read_write` scope (the default for e2-micro images), these
# calls return 403. They MUST be run from a workstation with broader
# auth -- typically the laptop where you have `gcloud auth login` as the
# project owner -- BEFORE running install.sh. SKIP_GCS_SETUP=1 short-
# circuits this section so install.sh is rerunnable on the VM.
#
# The probe distinguishes "first install on this VM" from "rerun":
# `gsutil ls -b` against a missing bucket returns 1, and we still want
# to fail loud in that case (so the operator notices they need to do
# the laptop-side setup first). Once the bucket exists, the rest of the
# section is idempotent metadata work; we attempt it and tolerate 403
# (already configured by an earlier laptop-side run).
if [ "${SKIP_GCS_SETUP:-0}" = "1" ]; then
  echo "==> GCS backup bucket setup skipped (SKIP_GCS_SETUP=1)"
elif ! gsutil -q ls -b "gs://${BACKUP_BUCKET}" >/dev/null 2>&1; then
  echo "ERROR: gs://${BACKUP_BUCKET} does not exist and the VM's default" >&2
  echo "service account cannot create buckets. Run this once from a" >&2
  echo "workstation with project-owner gcloud auth:" >&2
  echo "  gcloud storage buckets create gs://${BACKUP_BUCKET} \\" >&2
  echo "    --project=${GCP_PROJECT} --location=${GCP_REGION} \\" >&2
  echo "    --default-storage-class=STANDARD --uniform-bucket-level-access" >&2
  echo "  gcloud storage buckets update gs://${BACKUP_BUCKET} --versioning" >&2
  echo "  # then apply lifecycle from the JSON in install.sh and re-run." >&2
  echo "Or re-run install.sh with SKIP_GCS_SETUP=1 to defer setup." >&2
  exit 1
else
  echo "==> GCS backup bucket already exists; applying versioning + lifecycle + IAM if allowed"
  gcloud storage buckets update "gs://${BACKUP_BUCKET}" --versioning 2>/dev/null \
    || echo "    (versioning update skipped -- already set or insufficient scope)"

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
  gcloud storage buckets update "gs://${BACKUP_BUCKET}" --lifecycle-file="$LIFECYCLE_JSON" 2>/dev/null \
    || echo "    (lifecycle update skipped -- already set or insufficient scope)"
  rm -f "$LIFECYCLE_JSON"

  VM_SA="$(curl -sS -H 'Metadata-Flavor: Google' \
    http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email || true)"
  if [ -n "$VM_SA" ]; then
    gcloud storage buckets add-iam-policy-binding "gs://${BACKUP_BUCKET}" \
      --member="serviceAccount:${VM_SA}" \
      --role="roles/storage.objectAdmin" >/dev/null 2>&1 \
      && echo "    granted roles/storage.objectAdmin to ${VM_SA}" \
      || echo "    (IAM binding skipped -- already set or insufficient scope)"
  fi
fi

# gsutil caches the GCE metadata-server token in /root/.gsutil/gcecredcache.
# When the VM's OAuth scopes change (e.g. operator added devstorage.read_write
# to unbreak backups), the cached token retains the OLD scopes and uploads
# 403 until the cache is cleared. Wipe it on every install -- it's a free
# refresh.
rm -f /root/.gsutil/gcecredcache /root/.gsutil/credstore2 2>/dev/null || true

echo "==> install backup script + systemd units"
install -m 0755 "$SCRIPT_DIR/backup.sh" /usr/local/bin/yg-license-backup.sh
install -m 0644 "$SCRIPT_DIR/yg-license-backup.service" /etc/systemd/system/yg-license-backup.service
install -m 0644 "$SCRIPT_DIR/yg-license-backup.timer"   /etc/systemd/system/yg-license-backup.timer

echo "==> install events-pruning systemd units"
install -m 0644 "$SCRIPT_DIR/yg-license-prune-events.service" /etc/systemd/system/yg-license-prune-events.service
install -m 0644 "$SCRIPT_DIR/yg-license-prune-events.timer"   /etc/systemd/system/yg-license-prune-events.timer

# Surface the bucket name in the env file so backup.sh + future ops scripts
# read the same value.
ensure_env_line "BACKUP_BUCKET" "$BACKUP_BUCKET"

echo "==> systemctl daemon-reload + enable + start"
systemctl daemon-reload
systemctl enable --now duckdns-update.timer
systemctl start duckdns-update.service  # one-shot kick to register IP immediately
systemctl enable --now yg-license-server.service
systemctl enable --now yg-license-backup.timer
systemctl enable --now yg-license-prune-events.timer

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
