#!/bin/sh
# Refresh the DuckDNS A record for our hostname. Reads creds from
# /etc/yg-license-server/duckdns.env. Idempotent — DuckDNS responds "OK" or
# "KO". The cron-style timer is a belt-and-suspenders against IP changes
# (GCP static IPs don't change, but this guarantees no surprise downtime).
set -eu

ENV_FILE=/etc/yg-license-server/duckdns.env
[ -f "$ENV_FILE" ] || { echo "missing $ENV_FILE" >&2; exit 1; }
. "$ENV_FILE"

: "${DUCKDNS_DOMAIN:?DUCKDNS_DOMAIN unset}"
: "${DUCKDNS_TOKEN:?DUCKDNS_TOKEN unset}"

response=$(curl -fsS "https://www.duckdns.org/update?domains=${DUCKDNS_DOMAIN}&token=${DUCKDNS_TOKEN}&ip=" 2>&1)
echo "duckdns: $response"
[ "$response" = "OK" ] || { echo "duckdns update failed: $response" >&2; exit 1; }
