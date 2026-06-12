"""Backup/restore (v1.3.0).

Pins:
1. Golden round-trip: real data -> export -> wipe -> import -> the SAME
   license key still validates over /v1/check and the JWT verifies under
   the restored product pubkey (private keys survived byte-exact).
2. Encrypted round-trip under a KEK; wrong-KEK and no-KEK refusals.
3. Schema guard: alembic_version mismatch and unknown tables refuse.
4. Restore safety: typed phrase gate; pre-restore snapshot created first.
5. Retention: keep-N prunes oldest, pre-restore_ files never auto-pruned.
6. UI routes: create/list/download/delete/bulk + path traversal refused.
7. S3: upload best-effort (failure doesn't kill the backup), fake client.
"""
from __future__ import annotations

import io
import json
import tarfile

import pytest
from fastapi.testclient import TestClient

# ----- helpers -----------------------------------------------------------


def _login(client: TestClient) -> dict[str, str]:
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return {"ls_session": r.cookies["ls_session"]}


def _csrf(cookies: dict[str, str]) -> str:
    from app.config import get_settings
    from app.security import csrf_token
    return csrf_token(get_settings().session_secret, cookies["ls_session"])


def _seed(client: TestClient) -> str:
    """Product + preset + license; returns the plaintext license key."""
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200, r.text
    r2 = client.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={
            "email": "x@example.com", "valid_days": 30,
            "features": {"ai_api_included": True, "ai_included_usd_cap": 20},
        },
    )
    assert r2.status_code == 200, r2.text
    return r2.json()["key"]


def _check_ok(client: TestClient, key: str) -> dict:
    r = client.post("/v1/check", json={"key": key, "install_id": "i1", "version": "1.0.0"})
    assert r.status_code == 200, r.text
    return r.json()


def _wipe_db() -> None:
    from app.db import SessionLocal
    from app.models import Base
    with SessionLocal() as s:
        for t in reversed(Base.metadata.sorted_tables):
            s.execute(t.delete())
        s.commit()


# ----- round-trips ----------------------------------------------------------


def test_plaintext_round_trip_license_survives(client: TestClient) -> None:
    from app import backup as bk
    from app.db import SessionLocal
    key = _seed(client)
    pub = client.get("/v1/products/asm/pubkey").text

    with SessionLocal() as s:
        data = bk.export_archive(s)
    _wipe_db()
    r = client.post("/v1/check", json={"key": key, "install_id": "i1", "version": "1.0.0"})
    assert r.status_code == 401  # really gone

    with SessionLocal() as s:
        manifest = bk.import_archive(s, data)
    assert manifest["tables"]["licenses"] == 1

    body = _check_ok(client, key)
    assert body["features"] == {"ai_api_included": True, "ai_included_usd_cap": 20}
    import jwt as jwt_lib
    claims = jwt_lib.decode(
        body["jwt"], pub, algorithms=["EdDSA"], audience="asm",
        options={"verify_exp": False},
    )
    assert claims["product"] == "asm"
    assert client.get("/v1/products/asm/pubkey").text == pub


def test_encrypted_round_trip_and_wrong_kek(make_client, tmp_path) -> None:
    from cryptography.fernet import Fernet
    kek = Fernet.generate_key().decode()
    client = make_client(LICENSE_KEY_ENCRYPTION_KEY=kek)
    from app import backup as bk
    from app.db import SessionLocal
    key = _seed(client)

    with SessionLocal() as s:
        data, encrypted = bk.wrap(bk.export_archive(s))
    assert encrypted and data.startswith(bk.ENCRYPTED_MAGIC)

    _wipe_db()
    with SessionLocal() as s:
        bk.import_archive(s, data)
    _check_ok(client, key)

    # Same archive against a server with a DIFFERENT KEK -> refused.
    # NB: reference ValidationFailed through the module — each make_client
    # reloads app.services.errors, so a class imported before the reload
    # would no longer be the class the new code raises.
    import app.services.errors as errors_mod
    make_client(LICENSE_KEY_ENCRYPTION_KEY=Fernet.generate_key().decode())
    from app.db import SessionLocal as SL2
    with SL2() as s, pytest.raises(errors_mod.ValidationFailed, match="decrypt failed"):
        bk.import_archive(s, data)
    # ...and against a server with NO KEK -> refused with a distinct message.
    # (explicit empty value: monkeypatched env persists across make_client
    # calls inside one test, so omitting the kwarg would keep the prior KEK)
    make_client(LICENSE_KEY_ENCRYPTION_KEY="")
    from app.db import SessionLocal as SL3
    with SL3() as s, pytest.raises(errors_mod.ValidationFailed, match="no kek"):
        bk.import_archive(s, data)


def test_unrecognized_bytes_refused(client: TestClient) -> None:
    from app import backup as bk
    from app.db import SessionLocal
    from app.services.errors import ValidationFailed
    with SessionLocal() as s, pytest.raises(ValidationFailed, match="not a recognized"):
        bk.import_archive(s, b"definitely not a backup")


# ----- schema guard ----------------------------------------------------------


def _tamper_manifest(data: bytes, **overrides) -> bytes:
    """Rewrite manifest.json inside a plaintext tar.gz archive."""
    src = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    out_buf = io.BytesIO()
    out = tarfile.open(fileobj=out_buf, mode="w:gz")
    for member in src.getmembers():
        blob = src.extractfile(member).read()
        if member.name == "manifest.json":
            manifest = json.loads(blob)
            manifest.update(overrides)
            blob = json.dumps(manifest).encode()
        info = tarfile.TarInfo(name=member.name)
        info.size = len(blob)
        out.addfile(info, io.BytesIO(blob))
    out.close()
    return out_buf.getvalue()


def test_alembic_mismatch_refused_when_both_known(client: TestClient) -> None:
    """Test DBs are unstamped (init_db), so fake the live side too: archive
    says revision A; stamp the DB with revision B -> refuse."""
    from sqlalchemy import text

    from app import backup as bk
    from app.db import SessionLocal
    from app.services.errors import ValidationFailed
    _seed(client)
    with SessionLocal() as s:
        data = bk.export_archive(s)
        s.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32))"))
        s.execute(text("INSERT INTO alembic_version VALUES ('liverev_b')"))
        s.commit()
    tampered = _tamper_manifest(data, alembic_version="bakrev_a")
    with SessionLocal() as s, pytest.raises(ValidationFailed, match="schema version mismatch"):
        bk.import_archive(s, tampered)


def test_unknown_table_in_archive_refused(client: TestClient) -> None:
    from app import backup as bk
    from app.db import SessionLocal
    from app.services.errors import ValidationFailed
    _seed(client)
    with SessionLocal() as s:
        data = bk.export_archive(s)
    tampered = _tamper_manifest(data, tables={"licenses": 1, "from_the_future": 3})
    with SessionLocal() as s, pytest.raises(ValidationFailed, match="schema version mismatch"):
        bk.import_archive(s, tampered)


# ----- restore service safety -------------------------------------------------


def test_restore_requires_exact_phrase(client: TestClient) -> None:
    from app import backup as bk
    from app.db import SessionLocal
    from app.services import backups as svc
    from app.services.errors import ValidationFailed
    key = _seed(client)
    with SessionLocal() as s:
        data = bk.export_archive(s)
    with SessionLocal() as s, pytest.raises(ValidationFailed, match="confirmation"):
        svc.restore_backup(s, data, confirmation_phrase="restore license server",
                           source="test")
    _check_ok(client, key)  # nothing was touched


def test_restore_writes_pre_restore_snapshot_and_event(client: TestClient) -> None:
    from app import backup as bk
    from app.db import SessionLocal
    from app.models import Event
    from app.services import backups as svc
    key = _seed(client)
    with SessionLocal() as s:
        data = bk.export_archive(s)
    with SessionLocal() as s:
        svc.restore_backup(s, data, confirmation_phrase=svc.RESTORE_PHRASE, source="test")
    snaps = [b for b in bk.list_local_backups() if b["pre_restore"]]
    assert len(snaps) == 1
    _check_ok(client, key)
    with SessionLocal() as s:
        ev = s.query(Event).filter_by(type="backup:restored").one()
        assert ev.payload["pre_restore_snapshot"] == snaps[0]["name"]


# ----- retention --------------------------------------------------------------


def test_retention_keeps_n_and_spares_pre_restore(client: TestClient) -> None:
    import os
    import time

    from app import backup as bk
    d = bk.backup_dir()
    now = time.time()
    names = []
    for i in range(5):
        name = f"{bk.BACKUP_PREFIX}v0.0.0_2026010{i + 1}-000000.tar.gz"
        (d / name).write_bytes(b"\x1f\x8b" + bytes([i]))
        os.utime(d / name, (now - (5 - i) * 3600, now - (5 - i) * 3600))
        names.append(name)
    pre = f"{bk.PRERESTORE_PREFIX}v0.0.0_20260101-000000.tar.gz"
    (d / pre).write_bytes(b"\x1f\x8bx")
    os.utime(d / pre, (now - 10 * 3600, now - 10 * 3600))

    deleted = bk.apply_local_retention(keep_count=2, max_age_days=0)
    assert sorted(deleted) == sorted(names[:3])     # 3 oldest scheduled pruned
    left = {b["name"] for b in bk.list_local_backups()}
    assert set(names[3:]) <= left and pre in left   # newest 2 + safety snapshot


# ----- UI routes ---------------------------------------------------------------


def test_ui_create_list_download_delete(client: TestClient) -> None:
    import re
    _seed(client)
    cookies = _login(client)
    r = client.post(
        "/admin/backups/create", data={"csrf_token": _csrf(cookies)},
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    m = re.search(r"created=([^&]+)", r.headers["location"])
    assert m, r.headers["location"]
    name = m.group(1)

    page = client.get("/admin/backups", cookies=cookies)
    assert page.status_code == 200 and name in page.text

    dl = client.get(f"/admin/backups/download/{name}", cookies=cookies)
    assert dl.status_code == 200 and dl.content[:2] == b"\x1f\x8b"  # no KEK -> plain gzip

    # path traversal shapes 404 without touching disk
    assert client.get("/admin/backups/download/..%2F..%2Fetc%2Fpasswd", cookies=cookies).status_code == 404
    assert client.get("/admin/backups/download/nope.tar.gz", cookies=cookies).status_code == 404

    r2 = client.post(
        f"/admin/backups/{name}/delete", data={"csrf_token": _csrf(cookies)},
        cookies=cookies, follow_redirects=False,
    )
    assert r2.status_code == 303
    from app import backup as bk
    assert bk.list_local_backups() == []


def test_ui_restore_round_trip(client: TestClient) -> None:
    import re

    from app.services import backups as svc
    key = _seed(client)
    cookies = _login(client)
    r = client.post(
        "/admin/backups/create", data={"csrf_token": _csrf(cookies)},
        cookies=cookies, follow_redirects=False,
    )
    name = re.search(r"created=([^&]+)", r.headers["location"]).group(1)
    _wipe_db()
    # cookies/session live in env, not DB -- but CSRF needs the session only.
    r2 = client.post(
        f"/admin/backups/{name}/restore",
        data={"confirmation_phrase": svc.RESTORE_PHRASE, "csrf_token": _csrf(cookies)},
        cookies=cookies, follow_redirects=False,
    )
    assert r2.status_code == 303 and "restored=1" in r2.headers["location"], r2.headers["location"]
    _check_ok(client, key)
    # wrong phrase -> error redirect, no restore
    r3 = client.post(
        f"/admin/backups/{name}/restore",
        data={"confirmation_phrase": "nope", "csrf_token": _csrf(cookies)},
        cookies=cookies, follow_redirects=False,
    )
    assert "error=restore+confirmation+mismatch" in r3.headers["location"]


def test_ui_restore_upload(client: TestClient) -> None:
    from app import backup as bk
    from app.db import SessionLocal
    from app.services import backups as svc
    key = _seed(client)
    with SessionLocal() as s:
        data = bk.export_archive(s)
    _wipe_db()
    cookies = _login(client)
    r = client.post(
        "/admin/backups/restore-upload",
        data={"confirmation_phrase": svc.RESTORE_PHRASE, "csrf_token": _csrf(cookies)},
        files={"file": ("b.tar.gz", data, "application/gzip")},
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303 and "restored=1" in r.headers["location"], r.headers["location"]
    _check_ok(client, key)


# ----- S3 best-effort -----------------------------------------------------------


class _FakeS3:
    def __init__(self, fail: bool = False):
        self.fail = fail
        self.objects: dict[str, bytes] = {}

    def put_object(self, Bucket: str, Key: str, Body: bytes):  # noqa: N803
        if self.fail:
            raise RuntimeError("bucket on fire")
        self.objects[Key] = Body


def test_s3_upload_and_best_effort_failure(make_client, monkeypatch) -> None:
    client = make_client(BACKUP_S3_BUCKET="test-bucket", BACKUP_S3_PREFIX="prefix")
    import app.backup_s3 as s3mod
    from app.db import SessionLocal
    from app.services import backups as svc
    _seed(client)

    fake = _FakeS3()
    monkeypatch.setattr(s3mod, "_client", lambda s: fake)
    with SessionLocal() as s:
        result = svc.create_backup(s, note="test")
    assert result.s3_key == f"prefix/{result.filename}"
    assert fake.objects[result.s3_key]
    assert result.s3_error is None

    # Upload failure: local backup still succeeds, error surfaced not raised.
    fake.fail = True
    with SessionLocal() as s:
        result2 = svc.create_backup(s, note="test")
    assert result2.s3_key is None and "bucket on fire" in result2.s3_error
    from app import backup as bk
    assert any(b["name"] == result2.filename for b in bk.list_local_backups())
