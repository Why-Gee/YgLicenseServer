"""Coverage for `python -m app.scripts.send_expiry_warnings`.

Verifies:
  - Licenses expiring within the smallest threshold (default 7d) get warned.
  - Licenses well outside all thresholds get NO warning.
  - Already-warned licenses (same threshold) get skipped on rerun (idempotent).
  - Revoked / disabled licenses don't get warned even when valid_until is soon.
  - --dry-run logs without sending or recording the event.
"""
from __future__ import annotations

import importlib
from unittest.mock import patch


def _setup(client, *, days_until_expiry: int, status: str = "active") -> str:
    """Create a product + license whose valid_until is `days_until_expiry`
    days from now. Returns license_id."""
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200, r.text
    r = client.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={"email": "x@example.com", "plan": "standard", "valid_days": days_until_expiry},
    )
    assert r.status_code == 200, r.text
    license_id = r.json()["license_id"]
    if status != "active":
        from app.db import SessionLocal
        from app.models import License
        with SessionLocal() as s:
            lic = s.query(License).filter_by(id=license_id).one()
            lic.status = status
            s.commit()
    return license_id


def _reload_sw():
    import app.scripts.send_expiry_warnings as sw
    importlib.reload(sw)
    return sw


def test_warns_license_inside_7d_window(make_client) -> None:
    c = make_client(RESEND_API_KEY="re_test_key")
    license_id = _setup(c, days_until_expiry=5)
    sw = _reload_sw()
    with patch.object(sw, "send_expiry_warning_email", return_value=True) as m:
        assert sw.run() == 0
    assert m.called, "expected an email send for a license 5 days from expiry"
    from app.db import SessionLocal
    from app.models import Event
    with SessionLocal() as s:
        evs = s.query(Event).filter(
            Event.license_id == license_id,
            Event.type.like("expiry_warning:%"),
        ).all()
        assert len(evs) == 1
        assert evs[0].type == "expiry_warning:7"


def test_no_warning_when_far_from_expiry(make_client) -> None:
    """A license 200 days out is outside every default threshold."""
    c = make_client(RESEND_API_KEY="re_test_key")
    _setup(c, days_until_expiry=200)
    sw = _reload_sw()
    with patch.object(sw, "send_expiry_warning_email", return_value=True) as m:
        assert sw.run() == 0
    assert not m.called


def test_idempotent_same_threshold(make_client) -> None:
    """Running twice doesn't double-send when no time has elapsed."""
    c = make_client(RESEND_API_KEY="re_test_key")
    _setup(c, days_until_expiry=5)
    sw = _reload_sw()
    with patch.object(sw, "send_expiry_warning_email", return_value=True) as m:
        sw.run()
        first_calls = m.call_count
        sw.run()
        second_calls = m.call_count
    assert first_calls == 1 and second_calls == 1, "second run must NOT re-send same threshold"


def test_revoked_license_not_warned(make_client) -> None:
    c = make_client(RESEND_API_KEY="re_test_key")
    _setup(c, days_until_expiry=5, status="revoked")
    sw = _reload_sw()
    with patch.object(sw, "send_expiry_warning_email", return_value=True) as m:
        sw.run()
    assert not m.called


def test_dry_run_does_not_send_or_record(make_client) -> None:
    c = make_client(RESEND_API_KEY="re_test_key")
    license_id = _setup(c, days_until_expiry=5)
    sw = _reload_sw()
    with patch.object(sw, "send_expiry_warning_email", return_value=True) as m:
        assert sw.run(dry_run=True) == 0
    assert not m.called
    from app.db import SessionLocal
    from app.models import Event
    with SessionLocal() as s:
        evs = s.query(Event).filter(
            Event.license_id == license_id,
            Event.type.like("expiry_warning:%"),
        ).count()
    assert evs == 0


def test_unset_resend_api_key_exits_clean(make_client) -> None:
    """No API key -> no sends, exit 0 (so the systemd unit doesn't crash-loop)."""
    c = make_client()  # default: no RESEND_API_KEY
    _setup(c, days_until_expiry=5)
    sw = _reload_sw()
    assert sw.run() == 0


def test_picks_most_urgent_threshold(make_client) -> None:
    """A license 10 days out should fire the 14d warning (smallest matching),
    not the 30d one."""
    c = make_client(RESEND_API_KEY="re_test_key")
    license_id = _setup(c, days_until_expiry=10)
    sw = _reload_sw()
    with patch.object(sw, "send_expiry_warning_email", return_value=True):
        sw.run()
    from app.db import SessionLocal
    from app.models import Event
    with SessionLocal() as s:
        ev_types = sorted(
            r.type for r in s.query(Event).filter(
                Event.license_id == license_id,
                Event.type.like("expiry_warning:%"),
            ).all()
        )
    assert ev_types == ["expiry_warning:14"]
