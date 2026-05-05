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
sed "s|\${IMAGE}|$IMAGE|g" "$SCRIPT_DIR/yg-license-server.service" \
  > /etc/systemd/system/yg-license-server.service

echo "==> install duckdns updater"
install -m 0755 "$SCRIPT_DIR/duckdns-update.sh" /usr/local/bin/duckdns-update.sh
install -m 0644 "$SCRIPT_DIR/duckdns-update.service" /etc/systemd/system/duckdns-update.service
install -m 0644 "$SCRIPT_DIR/duckdns-update.timer"   /etc/systemd/system/duckdns-update.timer

echo "==> systemctl daemon-reload + enable + start"
systemctl daemon-reload
systemctl enable --now duckdns-update.timer
systemctl start duckdns-update.service  # one-shot kick to register IP immediately
systemctl enable --now yg-license-server.service

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
