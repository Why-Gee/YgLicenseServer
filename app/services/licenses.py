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
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app import webhooks as wh
from app._time import utcnow as _utcnow
from app.license_keys import hash_key, make_display
from app.models import Customer, Event, Install, License, Product, WebhookDelivery
from app.security import is_safe_url_shape
from app.services.errors import Unsafe, ValidationFailed

log = logging.getLogger("license-server.services.licenses")

Scheduler = Callable[[Callable[[], None]], None]


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
    allow_http_webhook: bool = False,
    stripe_customer_id: str | None = None,
    note: str = "service/issue",
    send_email: bool = False,
) -> IssueResult:
    """Issue a new license. Resolves the customer by email (or stripe_customer_id
    when provided), creates them if absent, generates the key, optionally
    configures a webhook (mints a fresh secret). Caller decides whether to
    fire the resend email — UI handlers historically didn't, JSON API does.

    `features` is opaque consumer-owned JSON — LS never interprets keys.
    Typo-safe authoring lives client-side (feature presets + the structured
    editor in the admin UI), keeping this server product-agnostic.
    """
    features = dict(features or {})
    name_clean = (name or "").strip() or None
    if stripe_customer_id is not None:
        cust = db.query(Customer).filter_by(stripe_customer_id=stripe_customer_id).one_or_none()
    else:
        cust = db.query(Customer).filter_by(email=email).one_or_none()
    if cust is None:
        # First license for this customer -- safe to set the name from the
        # form because no other product is currently using a different one.
        cust = Customer(email=email, name=name_clean, stripe_customer_id=stripe_customer_id)
        db.add(cust)
        db.flush()
    # Renaming an EXISTING customer must be an explicit action against the
    # customer (POST /admin/customers/{id}/edit), not a side effect of
    # issuing a license for an unrelated product they happen to own. The
    # caller's `name=...` is silently ignored in this branch by design.

    webhook_url_clean = (webhook_url or "").strip() or None
    if webhook_url_clean and not is_safe_url_shape(
        webhook_url_clean, allow_http=allow_http_webhook,
    ):
        raise Unsafe("unsafe webhook url")
    webhook_secret_value = wh.generate_secret() if webhook_url_clean else None
    webhook_source_value = "admin" if webhook_url_clean else "self"

    key = f"{product.key_prefix}_" + secrets.token_urlsafe(32)
    lic = License(
        product_id=product.id,
        customer_id=cust.id,
        key=key,                           # deprecated; drop in a later release
        key_hash=hash_key(key),
        key_display=make_display(key),
        plan=plan,
        max_users=max_users,
        features=features,
        valid_until=_utcnow() + timedelta(days=valid_days),
        status="active",
        webhook_url=webhook_url_clean,
        webhook_secret=webhook_secret_value,
        webhook_url_source=webhook_source_value,
        allow_http_webhook=1 if allow_http_webhook else 0,
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


def set_status(
    db: Session, lic: License, new_status: str, *,
    note: str, schedule: Scheduler | None = None,
) -> None:
    """Apply a status transition. The webhook (if configured) is enqueued
    into `webhook_deliveries` inside this same transaction so a rollback
    drops both the status change and the queue insert; on commit, a fresh
    session is opened post-response to attempt the first send.

    Failures are NOT lost -- the row stays pending in `webhook_deliveries`
    for the retry worker to pick up.
    """
    previous = lic.status
    lic.status = new_status
    db.add(Event(
        license_id=lic.id, product_id=lic.product_id,
        type=f"status:{new_status}", note=note,
    ))
    delivery_id = None
    if lic.webhook_url and lic.webhook_secret:
        data = {
            "license_id": lic.id,
            "license_key": lic.key,
            "key": lic.key,
            "product_slug": lic.product.slug if lic.product else None,
            "customer_email": lic.customer.email if lic.customer else None,
            "previous_status": previous,
            "current_status": new_status,
        }
        d = wh.enqueue(
            db, url=lic.webhook_url, secret=lic.webhook_secret,
            event_type=wh.EVENT_STATUS_CHANGED, data=data,
            license_id=lic.id, product_id=lic.product_id,
        )
        delivery_id = d.id
    db.commit()
    if delivery_id:
        _run(lambda: wh.attempt_in_fresh_session(delivery_id), schedule)


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
    lic: License, *, url: str | None, rotate: bool, mint_on_url_change: bool,
    source: str = "admin",
    allow_http: bool | None = None,
) -> None:
    """Mutate `lic.webhook_url` + `lic.webhook_secret` + `lic.webhook_url_source`
    per rotate semantics.

    `source` records who wrote the URL: 'admin' for admin UI / JSON API,
    'self' for /v1/check self-registration. /v1/check refuses overrides
    against rows whose source is 'admin'.

    Mints a fresh secret when:
      - `rotate=True` (caller explicitly asked), OR
      - the license has no secret yet (first-time set), OR
      - `mint_on_url_change=True` AND the URL actually changed.

    `allow_http` (when not None) overrides `lic.allow_http_webhook` for the
    validation check; None means use whatever is already on the row. Caller
    passes True to flip the row's flag to True alongside setting an http URL;
    None preserves the existing flag value.

    `url=None` clears all three fields. Caller commits.
    """
    if url:
        effective_allow_http = (
            allow_http if allow_http is not None else bool(lic.allow_http_webhook)
        )
        if not is_safe_url_shape(url, allow_http=effective_allow_http):
            raise Unsafe("unsafe webhook url")
        should_mint = (
            rotate
            or not lic.webhook_secret
            or (mint_on_url_change and lic.webhook_url != url)
        )
        if should_mint:
            lic.webhook_secret = wh.generate_secret()
        lic.webhook_url = url
        lic.webhook_url_source = source
        if allow_http is not None:
            lic.allow_http_webhook = 1 if allow_http else 0
    else:
        lic.webhook_url = None
        lic.webhook_secret = None
        lic.webhook_url_source = "self"
        lic.allow_http_webhook = 0


@dataclass(frozen=True)
class EditResult:
    changed_fields: list[str]
    secret_changed: bool


def edit_license(
    db: Session, lic: License, *,
    plan: str,
    max_users: int,
    valid_until_raw: str,
    features_json: str = "{}",
    webhook_url: str = "",
    allow_http_webhook: bool | None = None,
    rotate_secret: bool = False,
    note: str = "service/edit",
    schedule: Scheduler | None = None,
) -> EditResult:
    """Edit a license's per-license fields: plan, max_users, valid_until,
    features, and webhook config. Does NOT touch the linked Customer -- a
    Customer is a tenant-wide row (one per email across all products on this
    server), so renaming the customer from a license-edit form would silently
    rename the same person on every other product. Rename via the dedicated
    /admin/customers/{id}/edit endpoint instead.
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

    new_url = webhook_url.strip() or None
    prev_secret = lic.webhook_secret
    # The license-edit form always carries the *existing* webhook URL, so a plain
    # "Save Changes" (editing plan/features/etc.) must NOT re-write the webhook
    # config. Doing so would relabel a self-registered URL as admin-source
    # (stopping /v1/check from echoing the secret) and could rotate the key.
    # Only touch the webhook when the admin actually changed the URL or asked to
    # rotate; otherwise an unrelated edit leaves source/secret/URL untouched.
    url_changed = new_url != lic.webhook_url
    if url_changed or rotate_secret:
        # Only relabel to admin-source when the admin actually CHANGED the URL
        # (taking ownership of it). A pure rotate (URL unchanged, just minting a
        # fresh secret) must preserve the existing source -- otherwise ticking
        # "Rotate signing secret on save" on a self-registered webhook would flip
        # it to admin and stop /v1/check echoing the new secret to the client.
        apply_webhook_config(
            lic, url=new_url, rotate=rotate_secret, mint_on_url_change=True,
            source=("admin" if url_changed else lic.webhook_url_source),
            allow_http=allow_http_webhook,
        )
    else:
        # URL unchanged + no rotate: keep URL/secret/source as-is (a plain edit
        # must not relabel a self-registered webhook as admin-source). Two narrow
        # exceptions that do NOT touch the source:
        #   - heal a URL-bearing row that's missing its secret (preserves the
        #     pre-fix behavior of backfilling a dead channel on save), and
        #   - apply the http-allow toggle in EITHER direction. The edit form now
        #     always posts an explicit flag (the checkbox has a hidden "0"
        #     companion), so un-ticking actually clears the row. The old form
        #     omitted an unchecked box, leaving this None ("preserve") and
        #     silently dropping the OFF direction. Re-validates the stored URL
        #     under the new flag, so disabling http on an http:// row fails fast.
        #     `allow_http_webhook is None` still means "leave alone" for
        #     programmatic callers that omit it.
        if new_url and not lic.webhook_secret:
            lic.webhook_secret = wh.generate_secret()
        if (
            allow_http_webhook is not None
            and bool(lic.allow_http_webhook) != allow_http_webhook
        ):
            if new_url and not is_safe_url_shape(new_url, allow_http=allow_http_webhook):
                raise Unsafe("unsafe webhook url")
            lic.allow_http_webhook = 1 if allow_http_webhook else 0
    secret_changed = lic.webhook_secret != prev_secret

    db.add(Event(
        license_id=lic.id, product_id=lic.product_id, type="license:edited",
        payload={"webhook": bool(new_url), "secret_changed": secret_changed},
        note=note,
    ))
    delivery_id = None
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
        d = wh.enqueue(
            db, url=lic.webhook_url, secret=lic.webhook_secret,
            event_type=wh.EVENT_UPDATED, data=data,
            license_id=lic.id, product_id=lic.product_id,
        )
        delivery_id = d.id
    db.commit()
    if delivery_id:
        _run(lambda: wh.attempt_in_fresh_session(delivery_id), schedule)
    return EditResult(changed_fields=changed, secret_changed=secret_changed)


def configure_webhook(
    db: Session, lic: License, *,
    url: str | None,
    rotate: bool,
    mint_on_url_change: bool = True,
    source: str = "admin",
    allow_http: bool | None = None,
    note: str = "service/webhook",
    payload_extra: dict | None = None,
) -> None:
    """Set / change / clear the license webhook URL + secret. Commits.

    `source` records provenance: 'admin' (default) for admin UI / JSON API
    callers, 'self' if a future self-service endpoint ever uses this wrapper.
    /v1/check refuses public_url overrides against 'admin' rows.

    `mint_on_url_change=True` matches the UI handler's convention (changing
    the URL implicitly rotates the secret). The JSON API path uses False so
    callers control rotation explicitly.
    """
    apply_webhook_config(
        lic, url=url, rotate=rotate, mint_on_url_change=mint_on_url_change,
        source=source, allow_http=allow_http,
    )
    payload = {"set": bool(url)}
    if payload_extra:
        payload.update(payload_extra)
    db.add(Event(
        license_id=lic.id, product_id=lic.product_id, type="webhook:updated",
        payload=payload, note=note,
    ))
    db.commit()


def convert_webhook_to_self(
    db: Session, lic: License, *, note: str = "service/convert-to-self",
) -> None:
    """Flip an admin-set webhook to `source='self'`:

    - Keeps the URL unchanged (one-click migration; no re-typing).
    - Rotates the signing secret (the new one will be echoed via /v1/check;
      the old admin-distributed one is now invalidated, which is desired —
      if the customer's receiver still verifies HMAC with the old secret
      they need to re-fetch it via /v1/check anyway).
    - Allows future /v1/check public_url updates against this license.

    See docs/v1.0-workouttracker-client-findings.md item 1. Commits.
    """
    if not lic.webhook_url:
        raise ValidationFailed("no webhook url to convert")
    if lic.webhook_url_source != "admin":
        raise ValidationFailed("already self-registered")
    old_secret = lic.webhook_secret
    lic.webhook_url_source = "self"
    lic.webhook_secret = wh.generate_secret()
    db.add(Event(
        license_id=lic.id, product_id=lic.product_id,
        type="webhook:converted_to_self",
        payload={
            "url": lic.webhook_url,
            "old_secret_invalidated": bool(old_secret),
        },
        note=note,
    ))
    db.commit()


@dataclass(frozen=True)
class WebhookTestResult:
    ok: bool
    status: int | None
    error: str | None


def test_webhook(lic: License, db: Session) -> WebhookTestResult:
    """Send a synthetic license.test event and record it in the delivery log.

    Does not mutate the license. Persists ONE terminal WebhookDelivery row
    (Stripe/GitHub-style: test sends appear in history with their response) —
    deliberately NOT routed through enqueue()/try_deliver(), which would dump
    the test into the durable retry queue (7 backoff attempts, lingering
    'pending'). Status is terminal ('delivered'/'abandoned') so the retry
    worker never re-picks it. Returns the result for the redirect banner."""
    if not lic.webhook_url or not lic.webhook_secret:
        raise ValidationFailed("no webhook configured")
    data = {
        "license_id": lic.id, "key": lic.key,
        "product_slug": lic.product.slug,
        "customer_email": lic.customer.email,
        "test": True,
    }
    ok, status, err = wh.deliver(
        url=lic.webhook_url, secret=lic.webhook_secret,
        event_type="license.test", data=data,
        allow_http=bool(lic.allow_http_webhook),
    )
    now = _utcnow()
    db.add(WebhookDelivery(
        license_id=lic.id, product_id=lic.product_id,
        url=lic.webhook_url, secret=lic.webhook_secret,
        event_type="license.test",
        payload_json=json.dumps(data, separators=(",", ":")),
        attempts=1,
        status="delivered" if ok else "abandoned",
        next_attempt_at=now, last_attempt_at=now,
        delivered_at=now if ok else None,
        last_error=None if ok else (err or "(no detail)")[:500],
        response_status=status,
        response_excerpt=((err or "")[:500] or None) if status is not None else None,
    ))
    db.commit()
    return WebhookTestResult(ok=ok, status=status, error=err)


# ----- delete -----------------------------------------------------------


@dataclass(frozen=True)
class _DeletedLicenseSnapshot:
    """Everything we need to fire the post-commit webhook for a deleted
    license. Captured before the row is gone so the webhook task doesn't
    try to dereference an ORM-detached instance."""

    license_id: str
    key: str
    product_slug: str
    customer_email: str
    webhook_url: str | None
    webhook_secret: str | None


def _delete_license_in_tx(
    db: Session, lic: License, *, note: str
) -> tuple[_DeletedLicenseSnapshot, str | None]:
    """Stage one license's deletion inside the current transaction. Does NOT
    commit -- the caller is responsible for one commit per logical operation
    so a partial failure rolls the whole batch back.

    Mutations applied:
      - INSERT audit Event(license:deleted) with snapshot payload
      - INSERT pending WebhookDelivery (if webhook configured) so the
        delete event lands in the retry queue atomically with the delete
      - UPDATE events SET license_id=NULL for this license (audit survives)
      - DELETE installs WHERE license_id=this
      - DELETE this license row

    Returns (snapshot, delivery_id). delivery_id is None when no webhook
    is configured; otherwise the caller schedules a post-commit attempt.
    """
    snapshot = _DeletedLicenseSnapshot(
        license_id=lic.id,
        key=lic.key,
        product_slug=lic.product.slug,
        customer_email=lic.customer.email,
        webhook_url=lic.webhook_url,
        webhook_secret=lic.webhook_secret,
    )
    db.add(Event(
        product_id=lic.product_id, type="license:deleted",
        payload={
            "license_id": snapshot.license_id,
            "key": snapshot.key,
            "product_slug": snapshot.product_slug,
            "customer_email": snapshot.customer_email,
        }, note=note,
    ))
    delivery_id = None
    if snapshot.webhook_url and snapshot.webhook_secret:
        data = {
            "license_id": snapshot.license_id,
            "license_key": snapshot.key,
            "key": snapshot.key,
            "product_slug": snapshot.product_slug,
            "customer_email": snapshot.customer_email,
        }
        d = wh.enqueue(
            db, url=snapshot.webhook_url, secret=snapshot.webhook_secret,
            event_type=wh.EVENT_DELETED, data=data,
            license_id=None,  # license row is about to disappear
            product_id=lic.product_id,
        )
        delivery_id = d.id
    db.query(Event).filter_by(license_id=lic.id).update({"license_id": None})
    db.query(Install).filter_by(license_id=lic.id).delete()
    db.delete(lic)
    return snapshot, delivery_id


def delete_license(
    db: Session, lic: License, *,
    schedule: Scheduler | None = None,
    note: str = "service/delete",
) -> None:
    """Delete a single license + cascade installs in one transaction. Fires
    a license.deleted webhook AFTER commit (the row is gone, so the snapshot
    captured pre-commit is what the webhook task uses).

    For bulk deletion (multiple licenses, or a product-cascade), use
    `delete_licenses_bulk` -- it batches everything into a single commit so
    a mid-loop failure rolls the entire group back.
    """
    snap, delivery_id = _delete_license_in_tx(db, lic, note=note)
    db.commit()
    if delivery_id:
        _run(lambda: wh.attempt_in_fresh_session(delivery_id), schedule)


def delete_licenses_bulk(
    db: Session, licenses: list[License], *,
    schedule: Scheduler | None = None,
    note: str = "service/delete",
) -> list[_DeletedLicenseSnapshot]:
    """Delete N licenses atomically: stage every delete inside one tx, then
    commit once, then fan out one webhook per license post-commit.

    Either all licenses get deleted (and their webhooks fire) or none do
    (commit rolls back, caller sees the SQLAlchemy exception). Returns the
    snapshots so the caller can report a per-license result (e.g. UI redirect
    counters).
    """
    pairs = [_delete_license_in_tx(db, lic, note=note) for lic in licenses]
    db.commit()
    for _snap, delivery_id in pairs:
        if delivery_id:
            _run(lambda d=delivery_id: wh.attempt_in_fresh_session(d), schedule)
    return [snap for snap, _ in pairs]


