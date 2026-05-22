"""TOTP MFA business logic — pure functions, no FastAPI types.

Secret + recovery codes live in the DB (`admin_mfa` table). Secret is
Fernet-encrypted (anyone with it can forge OTPs); recovery codes are stored
as SHA-256 hex digests (one-way; we can verify a candidate but not recover
the plaintext). Single-row table, `id == 1` enforced by check constraint.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass

import pyotp
from sqlalchemy.orm import Session

from app._time import utcnow
from app.keystore import decrypt_secret, encrypt_secret
from app.models import AdminMfa

ISSUER = "YgLicenseServer"
ACCOUNT = "admin"
RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_BYTES = 6  # ~12 hex chars => ~48 bits, plenty for one-use


@dataclass(frozen=True)
class EnrolStart:
    secret: str
    provisioning_uri: str


def _row(db: Session) -> AdminMfa | None:
    return db.query(AdminMfa).filter_by(id=1).one_or_none()


def get_state(db: Session) -> AdminMfa | None:
    """Returns the row if present; None if MFA has never been enrolled."""
    return _row(db)


def is_enabled(db: Session) -> bool:
    row = _row(db)
    return bool(row and row.enabled)


def start_enrol(db: Session) -> EnrolStart:
    """Generate a fresh base32 TOTP secret, store it Fernet-encrypted on
    the (new or existing) admin_mfa row with enabled=False. Returns the
    plaintext secret and the otpauth:// provisioning URI for the caller
    to render as a QR code."""
    secret = pyotp.random_base32()
    enc = encrypt_secret(secret)
    row = _row(db)
    if row is None:
        row = AdminMfa(id=1, enabled=0, secret_encrypted=enc)
        db.add(row)
    else:
        row.enabled = 0
        row.secret_encrypted = enc
        row.recovery_codes_hashed = None
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=ACCOUNT, issuer_name=ISSUER)
    return EnrolStart(secret=secret, provisioning_uri=uri)


def verify_enrol(db: Session, code: str) -> list[str] | None:
    """Verify a TOTP code against the pending enrolment. On success, flip
    enabled=True, generate + store + return recovery codes. Returns None
    on bad code (caller emits 400)."""
    row = _row(db)
    if row is None or row.secret_encrypted is None or row.enabled:
        return None
    secret = decrypt_secret(row.secret_encrypted)
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        return None
    codes = _generate_recovery_codes()
    row.enabled = 1
    row.recovery_codes_hashed = json.dumps([_hash(c) for c in codes])
    db.commit()
    return codes


def verify_login(db: Session, code: str) -> bool:
    """Verify either a TOTP code or a recovery code. Recovery codes are
    single-use: redeemed codes are removed from the stored list. Returns
    True on success, False otherwise."""
    row = _row(db)
    if row is None or not row.enabled or row.secret_encrypted is None:
        return False
    # Try TOTP first (cheap).
    secret = decrypt_secret(row.secret_encrypted)
    if pyotp.TOTP(secret).verify(code, valid_window=1):
        row.last_used_at = utcnow()
        db.commit()
        return True
    # Fallback to recovery codes (case-insensitive match, then single-use).
    stored = json.loads(row.recovery_codes_hashed or "[]")
    candidate = _hash(code.strip().upper())
    if candidate not in stored:
        return False
    stored.remove(candidate)
    row.recovery_codes_hashed = json.dumps(stored)
    row.last_used_at = utcnow()
    db.commit()
    return True


def disable(db: Session, code: str) -> bool:
    """Verify the supplied OTP or recovery code, then clear all MFA state.
    Returns True on success."""
    if not verify_login(db, code):
        return False
    row = _row(db)
    if row is None:
        return False
    row.enabled = 0
    row.secret_encrypted = None
    row.recovery_codes_hashed = None
    db.commit()
    return True


def regen_recovery(db: Session, code: str) -> list[str] | None:
    """Verify the supplied OTP, then generate + store + return a fresh
    set of recovery codes. Old codes are invalidated."""
    row = _row(db)
    if row is None or not row.enabled or row.secret_encrypted is None:
        return None
    secret = decrypt_secret(row.secret_encrypted)
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        return None
    codes = _generate_recovery_codes()
    row.recovery_codes_hashed = json.dumps([_hash(c) for c in codes])
    db.commit()
    return codes


def _generate_recovery_codes() -> list[str]:
    """Generate N hex recovery codes. Uppercase + numeric only so they
    survive copy/paste through email and terminals without ambiguity."""
    return [secrets.token_hex(RECOVERY_CODE_BYTES).upper() for _ in range(RECOVERY_CODE_COUNT)]


def _hash(code: str) -> str:
    """SHA-256 hex digest. Codes are uppercase + hex, so case is unambiguous;
    we still .upper() at verify time as a defensive step."""
    return hashlib.sha256(code.upper().encode()).hexdigest()
