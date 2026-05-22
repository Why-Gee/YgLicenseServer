"""Phase 1 security hardening — TDD tests for vulns 1-3 + H4.

Each test exercises one specific fix and is added BEFORE the fix is
implemented (red-green-refactor).
"""
from __future__ import annotations

from contextlib import contextmanager

import httpx
from fastapi.testclient import TestClient


@contextmanager
def _captured(monkeypatch, status: int = 200):
    sent: list[dict] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        sent.append({
            "url": str(req.url),
            "headers": dict(req.headers),
            "body": req.content.decode() if req.content else "",
        })
        return httpx.Response(status, content=b'{"ok":true}')

    test_client = httpx.Client(
        transport=httpx.MockTransport(_handler), follow_redirects=False,
    )
    import app.http_client as hc
    monkeypatch.setattr(hc, "_client", test_client)
    try:
        yield sent
    finally:
        test_client.close()


def _admin_login(client: TestClient) -> dict[str, str]:
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return {"ls_session": r.cookies["ls_session"]}


def _csrf_for(cookies: dict[str, str]) -> str:
    from app.config import get_settings
    from app.security import csrf_token
    return csrf_token(get_settings().session_secret, cookies["ls_session"])


def _form_post(client: TestClient, url: str, cookies: dict[str, str], data: dict | None = None, **kw):
    payload = dict(data or {})
    payload.setdefault("csrf_token", _csrf_for(cookies))
    return client.post(url, data=payload, cookies=cookies, **kw)


def _create_product(client: TestClient, slug: str = "asm") -> None:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": slug, "name": slug.upper(), "key_prefix": slug},
    )
    assert r.status_code == 200, r.text


def _issue_with_webhook(client: TestClient, slug: str, webhook_url: str) -> str:
    """Issue a license via the admin UI form so we can set a webhook URL.
    Returns the license id."""
    cookies = _admin_login(client)
    r = _form_post(
        client, f"/admin/products/{slug}/licenses", cookies,
        data={
            "email": "alice@example.com",
            "plan": "standard",
            "max_users": "10",
            "valid_days": "30",
            "features_json": "{}",
            "webhook_url": webhook_url,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    # Parse the redirect for the issued license id.
    loc = r.headers["location"]
    assert "issued=" in loc, loc
    return loc.split("issued=")[1].split("&")[0]


# ---------- H4: _fire_deleted_webhook --------------------------------------


def test_delete_product_fires_webhooks_without_crashing(client, monkeypatch):
    """delete_product with a webhook-configured license must NOT raise
    ImportError on _fire_deleted_webhook (currently a latent crash) AND
    must deliver one license.deleted webhook per license."""
    _create_product(client)
    with _captured(monkeypatch) as sent:
        _issue_with_webhook(client, "asm", "https://customer.example.com/webhook")
        cookies = _admin_login(client)
        # delete the product → cascade-deletes the license → should fire webhook.
        r = _form_post(
            client, "/admin/products/asm/delete", cookies, follow_redirects=False,
        )
        assert r.status_code == 303, r.text
    deleted = [s for s in sent if "license.deleted" in s["headers"].get("x-license-server-event", "")]
    assert len(deleted) == 1, f"expected 1 license.deleted webhook, got {sent}"

    from app.db import SessionLocal
    from app.models import WebhookDelivery
    with SessionLocal() as s:
        deliveries = s.query(WebhookDelivery).all()
        deleted_rows = [d for d in deliveries if d.event_type == "license.deleted"]
        assert len(deleted_rows) == 1, (
            f"expected exactly one WebhookDelivery row for license.deleted, "
            f"got {len(deleted_rows)}: {[(d.id, d.event_type) for d in deliveries]}"
        )
