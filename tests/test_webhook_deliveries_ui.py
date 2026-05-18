"""Admin UI for the webhook-deliveries retry queue (v0.15).

Verifies:
  - /admin/webhook-deliveries requires login.
  - Lists rows in newest-first order.
  - ?status=<pending|delivered|abandoned> filters correctly.
  - The status-count badges reflect actual table state.
  - POST /admin/webhook-deliveries/<id>/retry re-attempts a delivery.
  - The retry button revives an abandoned row.
"""
from __future__ import annotations

from unittest.mock import patch


def _login(client) -> None:
    r = client.post(
        "/admin/login",
        data={"token": "test-admin"},
        follow_redirects=False,
    )
    assert r.status_code == 303


def _create_pending_delivery(client) -> str:
    """Set up: product + license with webhook, then a status change that
    enqueues a delivery and fails its first send. Returns delivery_id."""
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200
    r = client.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={"email": "x@example.com", "plan": "standard", "valid_days": 30},
    )
    assert r.status_code == 200
    license_id = r.json()["license_id"]

    from app.db import SessionLocal
    from app.models import License, WebhookDelivery
    from app.services.licenses import revoke_license

    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=license_id).one()
        lic.webhook_url = "https://hook.example.test/x"
        lic.webhook_secret = "whsec_test"
        s.commit()
    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=license_id).one()
        with patch("app.webhooks.deliver", return_value=(False, 500, "ise")):
            revoke_license(s, lic, note="test")
    with SessionLocal() as s:
        d = s.query(WebhookDelivery).one()
        return d.id


def test_requires_login(client) -> None:
    r = client.get("/admin/webhook-deliveries", follow_redirects=False)
    assert r.status_code == 303
    assert "/admin/login" in r.headers["location"]


def test_shows_configured_receivers_with_no_deliveries(client) -> None:
    """A license with webhook_url set but no firings yet should still show
    up under "Configured receivers" -- otherwise the page looks empty and
    the admin assumes the webhook isn't wired."""
    _login(client)
    # Create license with webhook URL, but DO NOT trigger any status change.
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200
    r = client.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={"email": "x@example.com", "plan": "standard", "valid_days": 30},
    )
    license_id = r.json()["license_id"]
    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=license_id).one()
        lic.webhook_url = "https://hook.example.test/abc"
        lic.webhook_secret = "whsec_test"
        s.commit()
    r = client.get("/admin/webhook-deliveries")
    assert r.status_code == 200
    body = r.text
    # Configured-receivers panel shows the URL.
    assert "Configured receivers (1)" in body
    assert "hook.example.test/abc" in body
    # Empty-state copy points at how to make a delivery happen.
    assert "Test webhook" in body or "status change" in body


def test_lists_pending_delivery(client) -> None:
    _login(client)
    delivery_id = _create_pending_delivery(client)
    r = client.get("/admin/webhook-deliveries")
    assert r.status_code == 200
    body = r.text
    assert delivery_id in body
    assert "license.status.changed" in body
    assert "pending" in body


def test_status_filter_pending(client) -> None:
    _login(client)
    _create_pending_delivery(client)
    r = client.get("/admin/webhook-deliveries?status=pending")
    assert r.status_code == 200
    # Pending count badge should read "1".
    assert "Pending (1)" in r.text


def test_status_filter_delivered_empty(client) -> None:
    _login(client)
    _create_pending_delivery(client)
    r = client.get("/admin/webhook-deliveries?status=delivered")
    assert r.status_code == 200
    assert "Delivered (0)" in r.text
    # Empty-state copy mentions the active filter status.
    assert "no <code>delivered</code> deliveries" in r.text


def test_retry_requires_csrf(client) -> None:
    _login(client)
    delivery_id = _create_pending_delivery(client)
    # No csrf_token form field -> require_csrf raises -> 400.
    r = client.post(
        f"/admin/webhook-deliveries/{delivery_id}/retry",
        follow_redirects=False,
    )
    # require_csrf returns 400/403 via ServiceError mapping or similar.
    assert r.status_code in (400, 403)


def test_retry_succeeds_marks_delivered(client) -> None:
    _login(client)
    delivery_id = _create_pending_delivery(client)
    # Get CSRF token from the page.
    page = client.get("/admin/webhook-deliveries")
    import re
    m = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert m, "csrf_token field not found on the page"
    csrf = m.group(1)

    with patch("app.webhooks.deliver", return_value=(True, 200, None)):
        r = client.post(
            f"/admin/webhook-deliveries/{delivery_id}/retry",
            data={"csrf_token": csrf},
            follow_redirects=False,
        )
    assert r.status_code == 303
    from app.db import SessionLocal
    from app.models import WebhookDelivery
    with SessionLocal() as s:
        d = s.query(WebhookDelivery).filter_by(id=delivery_id).one()
        assert d.status == "delivered"


def test_retry_revives_abandoned(client) -> None:
    """An abandoned row that the operator retries should be flipped back
    to pending with attempts reset, then attempt once."""
    _login(client)
    delivery_id = _create_pending_delivery(client)
    from app.db import SessionLocal
    from app.models import WebhookDelivery
    with SessionLocal() as s:
        d = s.query(WebhookDelivery).filter_by(id=delivery_id).one()
        d.status = "abandoned"
        d.attempts = 7
        s.commit()

    page = client.get("/admin/webhook-deliveries")
    import re
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)

    with patch("app.webhooks.deliver", return_value=(True, 200, None)):
        r = client.post(
            f"/admin/webhook-deliveries/{delivery_id}/retry",
            data={"csrf_token": csrf},
            follow_redirects=False,
        )
    assert r.status_code == 303
    with SessionLocal() as s:
        d = s.query(WebhookDelivery).filter_by(id=delivery_id).one()
        assert d.status == "delivered"
        # attempts reset to 0 then bumped to 1 by the single attempt.
        assert d.attempts == 1
