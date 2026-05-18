"""Coverage for `python -m app.scripts.prune_events`.

Verifies:
  - Only heartbeat events get pruned by default.
  - Other event types (status, issued, license:*, etc.) are NEVER deleted.
  - --older-than-days bounds the cut precisely.
  - --dry-run reports the count without deleting.
  - --types lets the operator widen the prune set explicitly.
"""
from __future__ import annotations

from datetime import timedelta

from app._time import utcnow


def _seed_events(db_session, license_id: str, product_id: str) -> None:
    """Insert a deliberately varied set of events spanning the prune window."""
    from app.models import Event
    now = utcnow()
    rows = [
        # 200d old heartbeat -- should be pruned by default.
        Event(license_id=license_id, product_id=product_id, type="heartbeat",
              created_at=now - timedelta(days=200)),
        # 91d old heartbeat -- just over the default 90d threshold, prunes.
        Event(license_id=license_id, product_id=product_id, type="heartbeat",
              created_at=now - timedelta(days=91)),
        # 30d old heartbeat -- inside the threshold, stays.
        Event(license_id=license_id, product_id=product_id, type="heartbeat",
              created_at=now - timedelta(days=30)),
        # Old non-heartbeat events -- audit-relevant, stay forever.
        Event(license_id=license_id, product_id=product_id, type="issued",
              created_at=now - timedelta(days=500)),
        Event(license_id=license_id, product_id=product_id, type="status:revoked",
              created_at=now - timedelta(days=400)),
        Event(license_id=license_id, product_id=product_id, type="license:edited",
              created_at=now - timedelta(days=300)),
    ]
    for r in rows:
        db_session.add(r)
    db_session.commit()


def _setup(client) -> tuple[str, str]:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200
    product_id = r.json()["id"]
    r = client.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={"email": "x@example.com", "plan": "standard", "valid_days": 30},
    )
    assert r.status_code == 200
    license_id = r.json()["license_id"]
    return license_id, product_id


def test_prunes_only_old_heartbeats(client) -> None:
    license_id, product_id = _setup(client)
    from app.db import SessionLocal
    from app.models import Event
    with SessionLocal() as s:
        _seed_events(s, license_id, product_id)
    import importlib

    import app.scripts.prune_events as pe
    importlib.reload(pe)
    assert pe.run(older_than_days=90) == 0
    with SessionLocal() as s:
        # Only 1 heartbeat (the 30d one) plus non-heartbeats should remain.
        types_left = sorted(r.type for r in s.query(Event).all() if r.type != "issued")
        # Note: setup creates auto-issued events too; filter to deterministic set.
        heartbeats = s.query(Event).filter_by(type="heartbeat").count()
        issued = s.query(Event).filter_by(type="status:revoked").count()
        license_edited = s.query(Event).filter_by(type="license:edited").count()
    assert heartbeats == 1, f"only the 30d heartbeat should remain, types_left={types_left}"
    assert issued == 1
    assert license_edited == 1


def test_dry_run_does_not_delete(client) -> None:
    license_id, product_id = _setup(client)
    from app.db import SessionLocal
    from app.models import Event
    with SessionLocal() as s:
        _seed_events(s, license_id, product_id)
        before = s.query(Event).filter_by(type="heartbeat").count()
    import importlib

    import app.scripts.prune_events as pe
    importlib.reload(pe)
    assert pe.run(older_than_days=90, dry_run=True) == 0
    with SessionLocal() as s:
        after = s.query(Event).filter_by(type="heartbeat").count()
    assert before == after, "dry-run must not delete anything"


def test_custom_types_and_age(client) -> None:
    """Operator can widen the prune set. status:revoked at 400d gets caught."""
    license_id, product_id = _setup(client)
    from app.db import SessionLocal
    from app.models import Event
    with SessionLocal() as s:
        _seed_events(s, license_id, product_id)
    import importlib

    import app.scripts.prune_events as pe
    importlib.reload(pe)
    assert pe.run(older_than_days=350, types=("status:revoked",)) == 0
    with SessionLocal() as s:
        assert s.query(Event).filter_by(type="status:revoked").count() == 0
        # Heartbeats untouched in this run -- types filter was scoped.
        assert s.query(Event).filter_by(type="heartbeat").count() == 3


def test_rejects_zero_days(client) -> None:
    """older-than-days=0 would prune everything matching the type filter
    including events from this second; refuse loudly."""
    import importlib

    import app.scripts.prune_events as pe
    importlib.reload(pe)
    assert pe.run(older_than_days=0) == 2


def test_rejects_empty_types(client) -> None:
    import importlib

    import app.scripts.prune_events as pe
    importlib.reload(pe)
    assert pe.run(types=()) == 2
