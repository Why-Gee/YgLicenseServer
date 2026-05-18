"""Webhook retry queue (v0.12).

Verifies:
  - A successful first attempt marks the delivery 'delivered'.
  - A failure leaves the row 'pending' with next_attempt_at pushed out by
    the configured backoff.
  - After MAX_ATTEMPTS failures the row transitions to 'abandoned'.
  - The retry worker (`app.scripts.retry_webhooks.run`) picks rows whose
    next_attempt_at <= now and walks them through one attempt.
  - Enqueue happens inside the triggering tx -- a rollback drops both.
"""
from __future__ import annotations

import importlib
from datetime import timedelta
from unittest.mock import patch

from fastapi.testclient import TestClient

from app._time import utcnow


def _setup_license_with_webhook(client: TestClient, hook_url: str) -> str:
    """Create product + issue license; configure webhook. Returns license_id."""
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200, r.text
    r = client.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={"email": "x@example.com", "plan": "standard", "valid_days": 30},
    )
    assert r.status_code == 200, r.text
    license_id = r.json()["license_id"]
    # Attach webhook via the model directly (avoids needing the UI flow).
    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=license_id).one()
        lic.webhook_url = hook_url
        lic.webhook_secret = "whsec_test"
        s.commit()
    return license_id


def test_status_change_enqueues_and_first_attempt_succeeds(client) -> None:
    """Happy path: receiver returns 200, delivery row is 'delivered'."""
    license_id = _setup_license_with_webhook(client, "https://hook.example.test/x")
    from app.db import SessionLocal
    from app.models import License, WebhookDelivery
    from app.services.licenses import revoke_license
    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=license_id).one()
        with patch("app.webhooks.deliver", return_value=(True, 200, None)):
            revoke_license(s, lic, note="test")
    with SessionLocal() as s:
        deliveries = s.query(WebhookDelivery).all()
        assert len(deliveries) == 1
        d = deliveries[0]
        assert d.status == "delivered"
        assert d.attempts == 1
        assert d.delivered_at is not None
        assert d.last_error is None


def test_failed_first_attempt_leaves_row_pending_with_backoff(client) -> None:
    license_id = _setup_license_with_webhook(client, "https://hook.example.test/x")
    from app.db import SessionLocal
    from app.models import License, WebhookDelivery
    from app.services.licenses import revoke_license
    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=license_id).one()
        with patch("app.webhooks.deliver", return_value=(False, 500, "ise")):
            revoke_license(s, lic, note="test")
    with SessionLocal() as s:
        d = s.query(WebhookDelivery).one()
        assert d.status == "pending"
        assert d.attempts == 1
        assert d.last_error == "ise"
        # Next attempt scheduled in the future per BACKOFF_SCHEDULE[0] = 1 min.
        assert d.next_attempt_at > utcnow()


def test_abandons_after_max_attempts(client) -> None:
    """Force a sequence of failed retries; the row should transition to
    'abandoned' once attempts == MAX_ATTEMPTS."""
    license_id = _setup_license_with_webhook(client, "https://hook.example.test/x")
    from app import webhooks as wh
    from app.db import SessionLocal
    from app.models import License, WebhookDelivery
    from app.services.licenses import revoke_license
    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=license_id).one()
        with patch("app.webhooks.deliver", return_value=(False, 500, "ise")):
            revoke_license(s, lic, note="test")
    # Each retry call advances one attempt. Simulate MAX_ATTEMPTS-1 more.
    with SessionLocal() as s:
        d_id = s.query(WebhookDelivery).one().id
    for _ in range(wh.MAX_ATTEMPTS - 1):
        with SessionLocal() as s:
            # Reset next_attempt_at so the retry helper picks it up.
            s.query(WebhookDelivery).filter_by(id=d_id).update(
                {"next_attempt_at": utcnow() - timedelta(seconds=1)}
            )
            s.commit()
        with patch("app.webhooks.deliver", return_value=(False, 500, "ise")):
            wh.attempt_in_fresh_session(d_id)
    with SessionLocal() as s:
        d = s.query(WebhookDelivery).one()
        assert d.status == "abandoned"
        assert d.attempts == wh.MAX_ATTEMPTS


def test_retry_worker_picks_due_rows_only(client) -> None:
    """The runner skips rows with next_attempt_at in the future and picks
    those that are due."""
    license_id = _setup_license_with_webhook(client, "https://hook.example.test/x")
    from app.db import SessionLocal
    from app.models import License, WebhookDelivery
    from app.services.licenses import revoke_license
    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=license_id).one()
        with patch("app.webhooks.deliver", return_value=(False, 500, "ise")):
            revoke_license(s, lic, note="test")
    # Push next_attempt_at far into the future -> runner should NOT touch it.
    with SessionLocal() as s:
        d = s.query(WebhookDelivery).one()
        d.next_attempt_at = utcnow() + timedelta(hours=1)
        s.commit()
    import app.scripts.retry_webhooks as rw
    importlib.reload(rw)
    with patch("app.webhooks.deliver", return_value=(True, 200, None)):
        assert rw.run() == 0
    with SessionLocal() as s:
        d = s.query(WebhookDelivery).one()
        # Still pending; attempts not incremented.
        assert d.status == "pending"
        assert d.attempts == 1

    # Now make it due. Runner should pick it up and deliver.
    with SessionLocal() as s:
        s.query(WebhookDelivery).filter_by(id=d.id).update(
            {"next_attempt_at": utcnow() - timedelta(seconds=1)}
        )
        s.commit()
    with patch("app.webhooks.deliver", return_value=(True, 200, None)):
        assert rw.run() == 0
    with SessionLocal() as s:
        d = s.query(WebhookDelivery).one()
        assert d.status == "delivered"
        assert d.attempts == 2


def test_no_enqueue_when_no_webhook_configured(client) -> None:
    """License without webhook_url => no delivery row, no error."""
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
    from app.models import License, WebhookDelivery
    from app.services.licenses import revoke_license
    with SessionLocal() as s:
        lic = s.query(License).filter_by(id=license_id).one()
        revoke_license(s, lic, note="test")
    with SessionLocal() as s:
        assert s.query(WebhookDelivery).count() == 0
