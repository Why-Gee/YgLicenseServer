"""S3-compatible backup destination (AWS S3, Cloudflare R2, MinIO, GCS
S3-interop, …) — endpoint-configurable, boto3 imported lazily so deploys
without S3 never pay the import.

Config (env): BACKUP_S3_BUCKET enables it; BACKUP_S3_ENDPOINT /
BACKUP_S3_REGION / BACKUP_S3_ACCESS_KEY / BACKUP_S3_SECRET_KEY /
BACKUP_S3_PREFIX shape the client. Credentials may also come from the
ambient chain (instance profile, env) when the key pair is unset.
"""
from __future__ import annotations

import logging

from app.config import Settings, get_settings

log = logging.getLogger("license-server.backup-s3")


def s3_enabled(s: Settings | None = None) -> bool:
    return bool((s or get_settings()).backup_s3_bucket)


def _client(s: Settings):
    import boto3  # lazy: only S3-enabled deploys need it at runtime
    kwargs: dict = {}
    if s.backup_s3_endpoint:
        kwargs["endpoint_url"] = s.backup_s3_endpoint
    if s.backup_s3_region:
        kwargs["region_name"] = s.backup_s3_region
    if s.backup_s3_access_key and s.backup_s3_secret_key:
        kwargs["aws_access_key_id"] = s.backup_s3_access_key
        kwargs["aws_secret_access_key"] = s.backup_s3_secret_key
    return boto3.client("s3", **kwargs)


def _key(s: Settings, name: str) -> str:
    prefix = s.backup_s3_prefix.strip("/")
    return f"{prefix}/{name}" if prefix else name


def upload(name: str, data: bytes) -> str:
    """Upload one archive; returns the object key. Caller decides whether a
    failure is fatal (scheduled runs log + continue with the local copy)."""
    s = get_settings()
    key = _key(s, name)
    _client(s).put_object(Bucket=s.backup_s3_bucket, Key=key, Body=data)
    return key


def list_backups(prefix: str) -> list[dict]:
    """Objects under the configured prefix whose basename starts with
    `prefix` (BACKUP_PREFIX scoping, mirrors the local listing)."""
    s = get_settings()
    base = _key(s, prefix)
    out = []
    paginator = _client(s).get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=s.backup_s3_bucket, Prefix=base):
        for obj in page.get("Contents", []):
            out.append({
                "name": obj["Key"].rsplit("/", 1)[-1],
                "key": obj["Key"],
                "size": obj["Size"],
                "mtime": obj["LastModified"],
            })
    out.sort(key=lambda b: b["mtime"], reverse=True)
    return out


def delete_keys(keys: list[str]) -> None:
    s = get_settings()
    if keys:
        _client(s).delete_objects(
            Bucket=s.backup_s3_bucket,
            Delete={"Objects": [{"Key": k} for k in keys]},
        )


def apply_s3_retention(*, keep_count: int, max_age_days: int, backup_prefix: str) -> list[str]:
    """Same policy as local retention, applied to the bucket prefix."""
    from datetime import UTC, datetime
    files = list_backups(backup_prefix)
    drop = files[keep_count:] if keep_count > 0 else []
    if max_age_days > 0:
        cutoff = datetime.now(UTC).timestamp() - max_age_days * 86400
        kept = files[:keep_count] if keep_count > 0 else files
        drop += [b for b in kept if b["mtime"].timestamp() < cutoff]
    delete_keys([b["key"] for b in drop])
    return [b["name"] for b in drop]
