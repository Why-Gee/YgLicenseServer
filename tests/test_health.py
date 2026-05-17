"""Health/readiness probes (Kubernetes-convention paths).

/healthz is pure liveness — never inspects dependencies.
/readyz pings the DB; returns 503 when the DB is unreachable so external
monitors and load balancers can react.
"""
from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError


def test_healthz_returns_200_with_version(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert isinstance(body["version"], str)
    assert body["version"]


def test_readyz_returns_200_when_db_reachable(client: TestClient) -> None:
    r = client.get("/readyz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["db"] == "ok"
    # No KEK set + no encrypted rows -> sample_decrypt skipped, kek="unset".
    assert body["kek"] == "unset"
    assert body["sample_decrypt"] == "no_encrypted_rows"


def test_readyz_returns_503_when_db_errors(client: TestClient) -> None:
    import app.main as m

    def _boom():
        raise OperationalError("SELECT 1", {}, Exception("db down"))

    with patch.object(m, "SessionLocal", side_effect=_boom):
        r = client.get("/readyz")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "degraded"
    assert body["db"] == "OperationalError"


def test_readyz_sample_decrypts_when_kek_set(make_client) -> None:
    """With a KEK set + a product created, /readyz sample-decrypts the
    product's private_key_pem and reports kek=set, sample_decrypt=ok."""
    from cryptography.fernet import Fernet
    c = make_client(LICENSE_KEY_ENCRYPTION_KEY=Fernet.generate_key().decode())
    r = c.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200
    r = c.get("/readyz")
    assert r.status_code == 200
    body = r.json()
    assert body["kek"] == "set"
    assert body["sample_decrypt"] == "ok"


def test_readyz_returns_503_on_kek_mismatch(make_client) -> None:
    """KEK swap without rewrap -> sample-decrypt raises -> 503 with
    kek=mismatch so external monitors can page."""
    from cryptography.fernet import Fernet
    kek1 = Fernet.generate_key().decode()
    c = make_client(LICENSE_KEY_ENCRYPTION_KEY=kek1)
    r = c.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200

    # Now mutate the running settings to a different KEK without rewrapping.
    kek2 = Fernet.generate_key().decode()
    import importlib
    import os
    os.environ["LICENSE_KEY_ENCRYPTION_KEY"] = kek2
    import app.config as cfg
    importlib.reload(cfg)
    import app.keystore as ks
    importlib.reload(ks)

    r = c.get("/readyz")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "degraded"
    assert body["kek"] == "mismatch"
    assert body["sample_decrypt"] == "fail"


def test_health_legacy_alias_still_returns_200(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert isinstance(body["version"], str)
