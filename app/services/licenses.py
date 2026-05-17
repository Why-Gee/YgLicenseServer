"""License lifecycle.

Status transitions, issue, edit, delete, bulk-delete. Pure logic — no
FastAPI types. The router passes `schedule_after_commit` as a callable that
defers work until after the HTTP response has been sent (e.g. `bg.add_task`);
when None, the function runs synchronously. This lets the same service serve
both the form-driven UI (with BackgroundTasks) and JSON callers (no bg).
"""
from __future__ import annotations

import json
import logging
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app import webhooks as wh
from app.models import Customer, Event, Install, License, Product
from app.security import is_safe_url_shape
from app.services.errors import Unsafe, ValidationFailed

log = logging.getLogger("license-server.services.licenses")

Scheduler = Callable[[Callable[[], None]], None]


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _run(fn: Callable[[], None], schedule: Scheduler | None) -> None:
    if schedule is None:
        fn()
    else:
        schedule(fn)


# ----- issuance ---------------------------------------------------------


@dataclass(frozen=True)
class IssueResult:
    license: License
    customer: Customer
    product: Product


def issue_license(
    db: Session,
    *,
    product: Product,
    email: str,
    name: str | None = None,
    plan: str = "standard",
    max_users: int = 10,
    valid_days: int = 365,
    features: dict | None = None,
    webhook_url: str | None = None,
    stripe_customer_id: str | None = None,
    note: str = "service/issue",
    send_email: bool = False,
) -> IssueResult:
    """Issue a new license. Resolves the customer by email (or stripe_customer_id
    when provided), creates them if absent, generates the key, optionally
    configures a webhook (mints a fresh secret). Caller decides whether to
    fire the resend email — UI handlers historically didn't, JSON API does.
    """
    name_clean = (name or "").strip() or None
    if stripe_customer_id is not None:
        cust = db.query(Customer).filter_by(stripe_customer_id=stripe_customer_id).one_or_none()
    else:
        cust = db.query(Customer).filter_by(email=email).one_or_none()
    if cust is None:
        cust = Customer(email=email, name=name_clean, stripe_customer_id=stripe_customer_id)
        db.add(cust)
        db.flush()
    elif name_clean and cust.name != name_clean:
        cust.name = name_clean

    webhook_url_clean = (webhook_url or "").strip() or None
    if webhook_url_clean and not is_safe_url_shape(webhook_url_clean, allow_http=True):
        raise Unsafe("unsafe webhook url")
    webhook_secret_value = wh.generate_secret() if webhook_url_clean else None

    key = f"{product.key_prefix}_" + secrets.token_urlsafe(32)
    lic = License(
        product_id=product.id,
        customer_id=cust.id,
        key=key,
        plan=plan,
        max_users=max_users,
        features=features or {},
        valid_until=_utcnow() + timedelta(days=valid_days),
        status="active",
        webhook_url=webhook_url_clean,
        webhook_secret=webhook_secret_value,
    )
    db.add(lic)
    db.add(Event(
        license_id=lic.id, product_id=product.id, type="issued",
        payload={"plan": plan, "webhook": bool(webhook_url_clean)}, note=note,
    ))
    db.commit()
    db.refresh(lic)

    if send_email:
        # local import: app.email pulls in httpx at import time; routers may
        # not need it.
        from app.email import send_license_email
        send_license_email(to=cust.email, key=lic.key, product_name=product.name)
    return IssueResult(license=lic, customer=cust, product=product)


# ----- status transitions ------------------------------------------------


def _webhook_snapshot(lic: License) -> dict:
    """Snapshot just the fields a status-change webhook needs, so the
    scheduled task doesn't try to dereference an ORM-detached row."""
    return {
        "url": lic.webhook_url,
        "secret": lic.webhook_secret,
        "license_id": lic.id,
        "license_key": lic.key,
        "product_slug": lic.product.slug if lic.product else None,
        "customer_email": lic.customer.email if lic.customer else None,
        "status": lic.status,
    }


def _deliver_status_change(snapshot: dict, previous_status: str) -> None:
    if not snapshot["url"] or not snapshot["secret"]:
        return
    data = {
        "license_id": snapshot["license_id"],
        "license_key": snapshot["license_key"],
        "key": snapshot["license_key"],
        "product_slug": snapshot["product_slug"],
        "customer_email": snapshot["customer_email"],
        "previous_status": previous_status,
        "current_status": snapshot["status"],
    }
    wh.deliver(
        url=snapshot["url"], secret=snapshot["secret"],
        event_type=wh.EVENT_STATUS_CHANGED, data=data,
    )


def set_status(
    db: Session, lic: License, new_status: str, *,
    note: str, schedule: Scheduler | None = None,
) -> None:
    """Apply a status transition and fan the status-change webhook out via
    `schedule`. Commits before scheduling so receivers POSTing back into
    /v1/check immediately see the committed state, not a session preview.
    """
    previous = lic.status
    lic.status = new_status
    db.add(Event(
        license_id=lic.id, product_id=lic.product_id,
        type=f"status:{new_status}", note=note,
    ))
    db.commit()
    snapshot = _webhook_snapshot(lic)
    _run(lambda: _deliver_status_change(snapshot, previous), schedule)


def revoke_license(db: Session, lic: License, *, note: str = "service/revoke",
                   schedule: Scheduler | None = None) -> None:
    set_status(db, lic, "revoked", note=note, schedule=schedule)


def disable_license(db: Session, lic: License, *, note: str = "service/disable",
                    schedule: Scheduler | None = None) -> None:
    set_status(db, lic, "disabled", note=note, schedule=schedule)


def enable_license(db: Session, lic: License, *, note: str = "service/enable",
                   schedule: Scheduler | None = None) -> None:
    set_status(db, lic, "active", note=note, schedule=schedule)


# ----- edit + webhook config --------------------------------------------


def apply_webhook_config(
    lic: License, *, url: str | None, rotate: bool, mint_on_url_change: bool
) -> None:
    """Mutate `lic.webhook_url` + `lic.webhook_secret` per rotate semantics.

    Mints a fresh secret when:
      - `rotate=True` (caller explicitly asked), OR
      - the license has no secret yet (first-time set), OR
      - `mint_on_url_change=True` AND the URL actually changed.

    `url=None` clears both fields. Caller commits.
    """
    if url:
        if url and not is_safe_url_shape(url, allow_http=True):
            raise Unsafe("unsafe webhook url")
        should_mint = (
            rotate
            or not lic.webhook_secret
            or (mint_on_url_change and lic.webhook_url != url)
        )
        if should_mint:
            lic.webhook_secret = wh.generate_secret()
        lic.webhook_url = url
    else:
        lic.webhook_url = None
        lic.webhook_secret = None


@dataclass(frozen=True)
class EditResult:
    changed_fields: list[str]
    secret_changed: bool


def edit_license(
    db: Session, lic: License, *,
    plan: str,
    max_users: int,
    valid_until_raw: str,
    customer_name: str = "",
    features_json: str = "{}",
    webhook_url: str = "",
    rotate_secret: bool = False,
    note: str = "service/edit",
    schedule: Scheduler | None = None,
) -> EditResult:
    """Edit a license. Mirrors the UI form's full semantics: parse features
    JSON, parse valid_until (date or datetime), apply customer_name overwrite,
    apply webhook config with mint_on_url_change=True, fire license.updated
    on any change.
    """
    try:
        features = json.loads(features_json) if features_json.strip() else {}
        if not isinstance(features, dict):
            raise ValueError
    except (ValueError, json.JSONDecodeError) as e:
        raise ValidationFailed("invalid features json") from e
    try:
        # HTML <input type="date"> posts YYYY-MM-DD. datetime-local posts
        # YYYY-MM-DDTHH:MM. Accept either.
        if "T" in valid_until_raw:
            new_valid_until = datetime.fromisoformat(valid_until_raw)
        else:
            new_valid_until = datetime.strptime(valid_until_raw, "%Y-%m-%d")
    except ValueError as e:
        raise ValidationFailed("invalid valid_until") from e

    changed: list[str] = []
    if lic.plan != plan:
        changed.append("plan")
    if lic.max_users != max_users:
        changed.append("max_users")
    if lic.valid_until != new_valid_until:
        changed.append("valid_until")
    if (lic.features or {}) != features:
        changed.append("features")
    lic.plan = plan
    lic.max_users = max_users
    lic.valid_until = new_valid_until
    lic.features = features

    name_clean = customer_name.strip() or None
    if (lic.customer.name or None) != name_clean:
        changed.append("customer_name")
    lic.customer.name = name_clean

    new_url = webhook_url.strip() or None
    prev_secret = lic.webhook_secret
    apply_webhook_config(lic, url=new_url, rotate=rotate_secret, mint_on_url_change=True)
    secret_changed = lic.webhook_secret != prev_secret

    db.add(Event(
        license_id=lic.id, product_id=lic.product_id, type="license:edited",
        payload={"webhook": bool(new_url), "secret_changed": secret_changed},
        note=note,
    ))
    db.commit()

    if changed and lic.webhook_url and lic.webhook_secret:
        data = {
            "license_id": lic.id,
            "license_key": lic.key,
            "key": lic.key,
            "product_slug": lic.product.slug if lic.product else None,
            "customer_email": lic.customer.email if lic.customer else None,
            "status": lic.status,
            "changed_fields": list(changed),
        }
        url, secret = lic.webhook_url, lic.webhook_secret
        _run(
            lambda: wh.deliver(
                url=url, secret=secret,
                event_type=wh.EVENT_UPDATED, data=data,
            ),
            schedule,
        )
    return EditResult(changed_fields=changed, secret_changed=secret_changed)


def configure_webhook(
    db: Session, lic: License, *,
    url: str | None,
    rotate: bool,
    mint_on_url_change: bool = True,
    note: str = "service/webhook",
    payload_extra: dict | None = None,
) -> None:
    """Set / change / clear the license webhook URL + secret. Commits.

    `mint_on_url_change=True` matches the UI handler's convention (changing
    the URL implicitly rotates the secret). The JSON API path uses False so
    callers control rotation explicitly.
    """
    apply_webhook_config(lic, url=url, rotate=rotate, mint_on_url_change=mint_on_url_change)
    payload = {"set": bool(url)}
    if payload_extra:
        payload.update(payload_extra)
    db.add(Event(
        license_id=lic.id, product_id=lic.product_id, type="webhook:updated",
        payload=payload, note=note,
    ))
    db.commit()


@dataclass(frozen=True)
class WebhookTestResult:
    ok: bool
    status: int | None
    error: str | None


def test_webhook(lic: License) -> WebhookTestResult:
    """Send a synthetic license.test event. Returns delivery result without
    mutating the license. Caller checks lic.webhook_url/_secret are set."""
    if not lic.webhook_url or not lic.webhook_secret:
        raise ValidationFailed("no webhook configured")
    ok, status, err = wh.deliver(
        url=lic.webhook_url, secret=lic.webhook_secret,
        event_type="license.test",
        data={
            "license_id": lic.id, "key": lic.key,
            "product_slug": lic.product.slug,
            "customer_email": lic.customer.email,
            "test": True,
        },
    )
    return WebhookTestResult(ok=ok, status=status, error=err)


# ----- delete -----------------------------------------------------------


def delete_license(
    db: Session, lic: License, *,
    schedule: Scheduler | None = None,
    note: str = "service/delete",
) -> None:
    """Delete a license + cascade installs. Fires a license.deleted webhook
    after commit (the row is gone, so we snapshot the fields beforehand).
    Audit event rows for this license get license_id NULL'd so history stays.
    """
    webhook_url = lic.webhook_url
    webhook_secret = lic.webhook_secret
    snapshot = {
        "license_id": lic.id,
        "key": lic.key,
        "product_slug": lic.product.slug,
        "customer_email": lic.customer.email,
    }
    db.add(Event(
        product_id=lic.product_id, type="license:deleted",
        payload=snapshot, note=note,
    ))
    db.query(Event).filter_by(license_id=lic.id).update({"license_id": None})
    db.query(Install).filter_by(license_id=lic.id).delete()
    db.delete(lic)
    db.commit()

    if webhook_url and webhook_secret:
        _run(
            lambda: wh.deliver_deleted(
                webhook_url=webhook_url, webhook_secret=webhook_secret, **snapshot
            ),
            schedule,
        )
