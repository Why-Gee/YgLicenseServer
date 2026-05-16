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
    assert body == {"status": "ok", "version": body["version"], "db": "ok"}


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


def test_health_legacy_alias_still_returns_200(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert isinstance(body["version"], str)
