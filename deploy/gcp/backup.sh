#!/bin/bash
# Nightly SQLite snapshot -> gzip -> upload to GCS. Wired up by install.sh
# as a systemd oneshot + timer (yg-license-backup.service / .timer).
#
# What this does:
#   1. `sqlite3 .backup` against the live DB at /var/lib/yg-license-server/license.db.
#      That's the standard online-backup API -- safe to run while the server
#      is serving traffic. We use python3's stdlib sqlite3 module (built-in)
#      so we don't need to install the sqlite3 CLI on the VM.
#   2. gzip the snapshot.
#   3. gsutil cp -- versioning is enabled on the bucket so each upload
#      becomes a new version of the same object; lifecycle policy expires
#      versions older than 30d. Net effect: ~30 daily snapshots retained,
#      no manual housekeeping.
#
# Exits non-zero on any failure (set -euo pipefail); journalctl will surface
# the error in the timer unit's status.
#
# To restore: download the desired version from GCS, gunzip, drop it in
# place of license.db (stop the service first, copy, chown 10001:10001,
# start). See docs/deploy/gcp.md for the full procedure.

set -euo pipefail

DB_PATH="${DB_PATH:-/var/lib/yg-license-server/license.db}"
BUCKET="${BACKUP_BUCKET:-yglicenseserver-backups}"
TMPDIR_BASE="${TMPDIR:-/tmp}"

if [ ! -f "$DB_PATH" ]; then
  echo "backup: source DB not found at $DB_PATH" >&2
  exit 1
fi

WORK="$(mktemp -d "$TMPDIR_BASE/yg-license-backup.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SNAP="$WORK/license-snapshot.db"

# Online .backup via the stdlib sqlite3 module (python3 ships with Debian
# 12 by default). This uses the same SQLite backup API as the `.backup`
# REPL command -- consistent snapshot, no writer pause beyond a few ms.
python3 - "$DB_PATH" "$SNAP" <<'PY'
import sqlite3, sys
src_path, dst_path = sys.argv[1], sys.argv[2]
src = sqlite3.connect(src_path)
dst = sqlite3.connect(dst_path)
with dst:
    src.backup(dst)
src.close()
dst.close()
PY

gzip -9 "$SNAP"
SNAP_GZ="${SNAP}.gz"

# Single object name; versioning on the bucket keeps the history. Suffix
# the timestamp on a separate metadata header so the user can grep `gsutil
# ls -L` output for a specific day, but the live object name stays stable.
DEST="gs://${BUCKET}/license.db.gz"
gsutil -q -h "x-goog-meta-snapshot-utc:${STAMP}" cp "$SNAP_GZ" "$DEST"

logger -t yg-license-backup "uploaded snapshot ${STAMP} to ${DEST}"
echo "backup: ok ${STAMP} -> ${DEST}"
