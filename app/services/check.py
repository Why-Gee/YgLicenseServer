"""/v1/check business logic — validate license, upsert install, mint JWT."""
from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app import webhooks
from app._time import utcnow as _utcnow
from app.models import Event, Install, License
from app.security import is_safe_url_shape
from app.services.errors import ServiceError
from app.signing import sign_license_jwt

log = logging.getLogger("license-server.services.check")


class CheckRejected(ServiceError):
    """License failed validation. `.reason` mirrors the legacy /v1/check
    error payload so existing clients keep working without translation."""

    def __init__(self, reason: str, *, http_status: int = 401) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status


@dataclass(frozen=True)
class CheckResult:
    jwt: str
    license: License


def check_license(
    db: Session, *,
    key: str,
    install_id: str,
    version: str,
    public_url: str | None,
    client_ip_hash: str | None,
) -> CheckResult:
    """Validate a license + record a heartbeat. Caller passes in the hashed
    client IP (router computes it from request headers — kept out of services
    to keep them framework-free)."""
    lic = db.query(License).filter_by(key=key).one_or_none()
    if lic is None:
        raise CheckRejected("invalid_key")
    if lic.status == "revoked":
        raise CheckRejected("revoked")
    if lic.status == "disabled":
        raise CheckRejected("disabled")
    if lic.valid_until < _utcnow():
        raise CheckRejected("expired")

    # Self-registered webhook URL. Strip trailing slash, validate, upsert
    # only when changed so we don't churn the row on every heartbeat.
    if public_url is not None and public_url.strip():
        candidate = public_url.strip().rstrip("/")
        if len(candidate) > 500 or not is_safe_url_shape(
            candidate, allow_http=bool(lic.allow_http_webhook),
        ):
            raise CheckRejected("invalid_public_url", http_status=400)
        if lic.webhook_url != candidate:
            # Admin-managed URLs are locked against /v1/check overrides.
            if lic.webhook_url_source == "admin":
                log.warning(
                    "license %s refused public_url override of admin-set URL", lic.id,
                )
                db.add(Event(
                    license_id=lic.id, product_id=lic.product_id,
                    type="webhook:override_refused",
                    payload={"attempted_url": candidate, "kept_url": lic.webhook_url},
                    note="service/check",
                ))
                db.commit()
                raise CheckRejected("webhook_url_locked", http_status=409)
            log.info("license %s webhook_url updated to %s", lic.id, candidate)
            db.add(Event(
                license_id=lic.id, product_id=lic.product_id,
                type="webhook:self-registered",
                payload={
                    "previous_url": lic.webhook_url,
                    "new_url": candidate,
                    "via": "v1_check",
                },
                note="service/check",
            ))
            lic.webhook_url = candidate
            lic.webhook_url_source = "self"
            # First time the customer self-registers → mint a secret so the
            # response can carry it. Re-self-registration of the same URL
            # leaves the existing secret in place.
            if not lic.webhook_secret:
                lic.webhook_secret = webhooks.generate_secret()

    install = (
        db.query(Install)
        .filter_by(license_id=lic.id, install_id=install_id)
        .one_or_none()
    )
    if install is None:
        install = Install(
            license_id=lic.id,
            install_id=install_id,
            version=version,
            ip_addr_hash=client_ip_hash,
        )
        db.add(install)
    else:
        install.version = version
        install.last_seen_at = _utcnow()
        install.ip_addr_hash = client_ip_hash

    token, _exp = sign_license_jwt(
        product=lic.product,
        license_id=lic.id,
        install_id=install_id,
        plan=lic.plan,
        max_users=lic.max_users,
        features=lic.features or {},
        valid_until=lic.valid_until,
    )
    db.add(Event(
        license_id=lic.id, product_id=lic.product_id, type="heartbeat",
        payload={"version": version, "install_id": install_id},
    ))
    db.commit()
    return CheckResult(jwt=token, license=lic)
