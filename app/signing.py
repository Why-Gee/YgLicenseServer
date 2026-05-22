"""Per-product Ed25519 keypair management + JWT signing."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.config import get_settings
from app.keystore import decrypt_pem
from app.models import Product


def generate_keypair() -> tuple[str, str]:
    """Generate a fresh Ed25519 keypair. Returns (private_pem, public_pem) as PEM strings."""
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def sign_license_jwt(
    *,
    product: Product,
    license_id: str,
    install_id: str,
    plan: str,
    max_users: int,
    features: dict,
    valid_until: datetime,
) -> tuple[str, datetime]:
    """Sign a JWT with the product's private key. Returns (jwt, exp_at_utc)."""
    s = get_settings()
    now = datetime.now(UTC)
    # Naive datetimes from older rows are assumed-UTC (the storage convention);
    # tz-aware values get converted, never relabeled.
    vu = valid_until.replace(tzinfo=UTC) if valid_until.tzinfo is None else valid_until.astimezone(UTC)
    cap = min(now + timedelta(days=s.jwt_ttl_days), vu)
    payload = {
        "iss": product.jwt_issuer,
        # opaque per-product id (UUID); survives slug rename, future-proofs key
        # rotation. Carried as a payload claim (not the JWS header) -- pyjwt
        # and most libraries ignore unknown payload claims, so adding it does
        # not break existing clients.
        "kid": product.id,
        # v1.0+ breaking change: aud = product.slug. pyjwt validates aud
        # whenever it is present, so clients MUST pass audience=product_slug
        # to jwt.decode (or options={"verify_aud": False}) or they will
        # receive InvalidAudienceError. Was deliberately omitted in v0.22.
        "aud": product.slug,
        "iat": int(now.timestamp()),
        "exp": int(cap.timestamp()),
        "product": product.slug,
        "license_id": license_id,
        "install_id": install_id,
        "plan": plan,
        "max_users": max_users,
        "features": features,
        "valid_until": int(vu.timestamp()),
    }
    # Private key may be stored wrapped (KEK envelope) or as legacy plaintext;
    # decrypt_pem handles both shapes.
    private_pem = decrypt_pem(product.private_key_pem)
    return jwt.encode(payload, private_pem, algorithm="EdDSA"), cap
