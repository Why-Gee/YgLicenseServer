"""Backup archive format: engine-agnostic logical dump of the whole DB.

Why logical (JSONL per table) and not a raw DB file copy:
- works identically for SQLite and Postgres, in BOTH directions (a backup
  taken on SQLite restores onto Postgres and vice versa — covers a future
  engine migration for free);
- restorable from inside the running app (no file-swap + service restart);
- schema-version stamped, so a restore against a different schema is
  refused instead of silently corrupting.

The VM-level raw snapshot (deploy/gcp/backup.sh -> GCS) remains as
infrastructure-level disaster recovery; this module is the operator-facing
layer (admin UI + scheduled script, local/S3 destinations).

Archive layout (tar.gz, possibly Fernet-wrapped — see ENCRYPTED_MAGIC):
    manifest.json            {format, format_version, app_version,
                              alembic_version, created_at, tables: {name: n}}
    tables/<table>.jsonl     one JSON object per row, column -> value;
                             datetimes as ISO strings (re-typed on import
                             from column metadata, so no value markers)

Encryption: when LICENSE_KEY_ENCRYPTION_KEY is set, the tar.gz bytes are
Fernet-encrypted under a key derived via HKDF-SHA256 with a backup-specific
info string (never the raw KEK — domain separation). Restoring needs the
same KEK in env. Without a KEK the archive is plaintext gzip (dev mode).
"""
from __future__ import annotations

import base64
import io
import json
import re
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import DateTime, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import __version__ as APP_VERSION
from app.config import get_settings
from app.models import Base
from app.services.errors import ValidationFailed

FORMAT_NAME = "yg-license-server-backup"
FORMAT_VERSION = 1
ENCRYPTED_MAGIC = b"YGLSBAK1"
_GZIP_MAGIC = b"\x1f\x8b"
_HKDF_INFO = b"yg-license-server/backup/v1"

# Scheduled/manual backups carry this prefix; retention ONLY prunes it.
# pre-restore_ safety snapshots are never auto-pruned (manual cleanup).
BACKUP_PREFIX = "yg-ls-backup_"
PRERESTORE_PREFIX = "pre-restore_"
FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


# ----- crypto -------------------------------------------------------------


def backup_fernet() -> Fernet | None:
    """Fernet keyed by HKDF(KEK, backup info string), or None when no KEK
    is configured (plaintext dev mode)."""
    kek = get_settings().key_encryption_key
    if not kek:
        return None
    raw = HKDF(
        algorithm=SHA256(), length=32, salt=None, info=_HKDF_INFO,
    ).derive(kek.encode())
    return Fernet(base64.urlsafe_b64encode(raw))


def wrap(raw_targz: bytes) -> tuple[bytes, bool]:
    """Encrypt the archive when a KEK is configured. Returns (data, encrypted)."""
    f = backup_fernet()
    if f is None:
        return raw_targz, False
    return ENCRYPTED_MAGIC + f.encrypt(raw_targz), True


def unwrap(data: bytes) -> bytes:
    """Inverse of wrap(); accepts either shape, raises ValidationFailed on
    wrong key / unrecognized bytes."""
    if data.startswith(ENCRYPTED_MAGIC):
        f = backup_fernet()
        if f is None:
            raise ValidationFailed("backup encrypted but no kek")
        try:
            return f.decrypt(data[len(ENCRYPTED_MAGIC):])
        except InvalidToken as e:
            raise ValidationFailed("backup decrypt failed") from e
    if data.startswith(_GZIP_MAGIC):
        return data
    raise ValidationFailed("not a recognized backup file")


# ----- export ---------------------------------------------------------------


def current_alembic_version(db: Session) -> str | None:
    """The DB's stamped schema revision; None when the table doesn't exist
    (test DBs built via init_db skip alembic)."""
    try:
        row = db.execute(text("SELECT version_num FROM alembic_version")).first()
        return row[0] if row else None
    except SQLAlchemyError:
        db.rollback()
        return None


def _encode_value(v: Any) -> Any:
    if isinstance(v, datetime):
        return v.isoformat()
    return v


def export_archive(db: Session) -> bytes:
    """Dump every ORM table to a tar.gz (NOT yet encrypted — see wrap())."""
    tables = Base.metadata.sorted_tables
    counts: dict[str, int] = {}
    files: dict[str, bytes] = {}
    for table in tables:
        rows = db.execute(table.select()).mappings().all()
        counts[table.name] = len(rows)
        lines = [
            json.dumps({k: _encode_value(v) for k, v in row.items()})
            for row in rows
        ]
        files[f"tables/{table.name}.jsonl"] = ("\n".join(lines)).encode()
    manifest = {
        "format": FORMAT_NAME,
        "format_version": FORMAT_VERSION,
        "app_version": APP_VERSION,
        "alembic_version": current_alembic_version(db),
        "created_at": datetime.now(UTC).isoformat(),
        "tables": counts,
    }
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        payload = {"manifest.json": json.dumps(manifest, indent=2).encode(), **files}
        for name, blob in payload.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(blob)
            tar.addfile(info, io.BytesIO(blob))
    return buf.getvalue()


def make_filename(*, encrypted: bool, prefix: str = BACKUP_PREFIX) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    ext = "lsbak" if encrypted else "tar.gz"
    return f"{prefix}v{APP_VERSION}_{stamp}.{ext}"


# ----- import ---------------------------------------------------------------


def read_manifest(data: bytes) -> dict:
    """Manifest from a (possibly encrypted) archive. Validates format."""
    raw = unwrap(data)
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
            member = tar.extractfile("manifest.json")
            if member is None:
                raise ValidationFailed("backup missing manifest")
            manifest = json.loads(member.read())
    except (tarfile.TarError, KeyError, json.JSONDecodeError) as e:
        raise ValidationFailed("not a recognized backup file") from e
    if manifest.get("format") != FORMAT_NAME:
        raise ValidationFailed("not a recognized backup file")
    if manifest.get("format_version") != FORMAT_VERSION:
        raise ValidationFailed("unsupported backup format version")
    return manifest


def _decode_row(table, row: dict) -> dict:
    out = {}
    for col in table.columns:
        v = row.get(col.name)
        if v is not None and isinstance(col.type, DateTime):
            v = datetime.fromisoformat(v)
        out[col.name] = v
    return out


def import_archive(db: Session, data: bytes) -> dict:
    """Full-replace restore: wipe every table, load the archive's rows, one
    transaction. Returns the manifest.

    Schema safety: refuses when the archive's alembic_version and the live
    DB's are BOTH known and differ — restoring across schema revisions
    would need per-revision migration logic this format doesn't carry.
    (Either side None = unstamped test/dev DB; the table set is still
    cross-checked below.)
    """
    manifest = read_manifest(data)
    raw = unwrap(data)
    db_rev = current_alembic_version(db)
    bak_rev = manifest.get("alembic_version")
    if db_rev and bak_rev and db_rev != bak_rev:
        raise ValidationFailed("backup schema version mismatch")

    tables = Base.metadata.sorted_tables
    known = {t.name for t in tables}
    archived = set(manifest.get("tables", {}))
    if not archived.issubset(known):
        raise ValidationFailed("backup schema version mismatch")

    rows_by_table: dict[str, list[dict]] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        for t in tables:
            if t.name not in archived:
                continue
            member = tar.extractfile(f"tables/{t.name}.jsonl")
            blob = member.read().decode() if member else ""
            rows_by_table[t.name] = [
                _decode_row(t, json.loads(line))
                for line in blob.splitlines() if line.strip()
            ]

    try:
        # Children first on delete, parents first on insert.
        for t in reversed(tables):
            db.execute(t.delete())
        for t in tables:
            rows = rows_by_table.get(t.name, [])
            if rows:
                db.execute(t.insert(), rows)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise
    return manifest


# ----- local destination + retention -----------------------------------------


def backup_dir() -> Path:
    d = Path(get_settings().backup_dir)
    d.mkdir(parents=True, exist_ok=True)
    return d


def safe_backup_path(name: str) -> Path:
    """Resolve a user-supplied backup filename inside backup_dir, refusing
    path traversal and unknown shapes."""
    if not FILENAME_RE.match(name) or not (
        name.startswith(BACKUP_PREFIX) or name.startswith(PRERESTORE_PREFIX)
    ):
        raise ValidationFailed("invalid backup filename")
    p = (backup_dir() / name).resolve()
    if p.parent != backup_dir().resolve():
        raise ValidationFailed("invalid backup filename")
    return p


def list_local_backups() -> list[dict]:
    """Newest first. Filename carries app version + stamp so listing never
    needs to decrypt archives."""
    out = []
    for p in backup_dir().iterdir():
        if not p.is_file():
            continue
        if not (p.name.startswith(BACKUP_PREFIX) or p.name.startswith(PRERESTORE_PREFIX)):
            continue
        st = p.stat()
        out.append({
            "name": p.name,
            "size": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime, tz=UTC),
            "encrypted": p.name.endswith(".lsbak"),
            "pre_restore": p.name.startswith(PRERESTORE_PREFIX),
        })
    out.sort(key=lambda b: b["mtime"], reverse=True)
    return out


def apply_local_retention(*, keep_count: int, max_age_days: int) -> list[str]:
    """Prune scheduled/manual backups (BACKUP_PREFIX only — pre-restore
    safety snapshots are never auto-pruned). Returns deleted names."""
    files = [b for b in list_local_backups() if not b["pre_restore"]]
    deleted: list[str] = []
    keep = files[:keep_count] if keep_count > 0 else files
    drop = files[keep_count:] if keep_count > 0 else []
    if max_age_days > 0:
        cutoff = datetime.now(UTC).timestamp() - max_age_days * 86400
        drop += [b for b in keep if b["mtime"].timestamp() < cutoff]
    for b in drop:
        (backup_dir() / b["name"]).unlink(missing_ok=True)
        deleted.append(b["name"])
    return deleted
