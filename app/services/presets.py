"""Feature presets — admin-defined authoring templates for license features.

LS is product-agnostic: the per-license `features` dict is opaque, consumer-
owned JSON, and LS attaches no semantics to any key. Presets exist purely so
admins can insert keys typo-free (with an overridable default value) instead
of hand-typing JSON. Validation here is SHAPE-only — "is the key well-formed,
does the value match the declared type" — never business rules; those belong
to the product consuming the JWT.
"""
from __future__ import annotations

import json
import math
import re

from sqlalchemy.orm import Session, joinedload

from app.models import Event, FeaturePreset, Product
from app.services.errors import Conflict, NotFound, ValidationFailed

VALUE_TYPES = ("bool", "number", "string", "json")

# Feature keys travel into JWTs and are read by client-side resolvers; keep
# them identifier-ish so a stray space / quote can't hide in one.
_KEY_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


def parse_value(value_type: str, raw: str):
    """Parse a raw form string into a JSON value of the declared type.

    bool   -> true/false (also 1/0, yes/no; case-insensitive)
    number -> int or float, finite (json.loads keeps 12 as int, 12.5 as float)
    string -> the raw text verbatim (no quoting needed)
    json   -> any valid JSON value
    """
    text_ = raw.strip()
    if value_type == "bool":
        low = text_.lower()
        if low in ("true", "1", "yes"):
            return True
        if low in ("false", "0", "no"):
            return False
        raise ValidationFailed("invalid preset value")
    if value_type == "number":
        try:
            val = json.loads(text_)
        except (ValueError, json.JSONDecodeError) as e:
            raise ValidationFailed("invalid preset value") from e
        if isinstance(val, bool) or not isinstance(val, int | float) or not math.isfinite(val):
            raise ValidationFailed("invalid preset value")
        return val
    if value_type == "string":
        return raw
    if value_type == "json":
        try:
            return json.loads(text_)
        except (ValueError, json.JSONDecodeError) as e:
            raise ValidationFailed("invalid preset value") from e
    raise ValidationFailed("invalid preset type")


def _validate(db: Session, *, product_id: str | None, key: str,
              exclude_id: str | None = None) -> None:
    if not _KEY_RE.match(key):
        raise ValidationFailed("invalid preset key")
    q = db.query(FeaturePreset).filter_by(product_id=product_id, key=key)
    if exclude_id:
        q = q.filter(FeaturePreset.id != exclude_id)
    if q.first() is not None:
        raise Conflict("preset exists")


def list_presets(db: Session) -> list[FeaturePreset]:
    """All presets, global first then per-product, keys alphabetical.
    Eager-loads product so templates can render the scope without N+1."""
    return (
        db.query(FeaturePreset)
        .options(joinedload(FeaturePreset.product))
        .order_by(
            FeaturePreset.product_id.is_(None).desc(),
            FeaturePreset.key.asc(),
        )
        .all()
    )


def presets_for_product(db: Session, product_id: str) -> list[FeaturePreset]:
    """Global presets + this product's, for the license-modal picker."""
    return (
        db.query(FeaturePreset)
        .filter(
            (FeaturePreset.product_id.is_(None))
            | (FeaturePreset.product_id == product_id)
        )
        .order_by(FeaturePreset.product_id.is_(None).desc(), FeaturePreset.key.asc())
        .all()
    )


def create_preset(
    db: Session, *,
    product_id: str | None,
    key: str,
    value_type: str,
    default_raw: str,
    note: str = "service/preset-create",
) -> FeaturePreset:
    """Create a preset. product_id None = global. Commits."""
    key = key.strip()
    if value_type not in VALUE_TYPES:
        raise ValidationFailed("invalid preset type")
    if product_id is not None and db.get(Product, product_id) is None:
        raise NotFound("product not found")
    _validate(db, product_id=product_id, key=key)
    preset = FeaturePreset(
        product_id=product_id,
        key=key,
        value_type=value_type,
        default_value=parse_value(value_type, default_raw),
    )
    db.add(preset)
    db.add(Event(
        product_id=product_id, type="preset:created",
        payload={"key": key, "value_type": value_type,
                 "scope": "product" if product_id else "global"},
        note=note,
    ))
    db.commit()
    db.refresh(preset)
    return preset


def update_preset(
    db: Session, preset: FeaturePreset, *,
    key: str,
    value_type: str,
    default_raw: str,
    note: str = "service/preset-edit",
) -> FeaturePreset:
    """Edit key/type/default in place. Scope (product vs global) is fixed at
    creation — moving a preset between scopes is delete + recreate, which
    keeps the audit trail honest about what existed where. Commits."""
    key = key.strip()
    if value_type not in VALUE_TYPES:
        raise ValidationFailed("invalid preset type")
    _validate(db, product_id=preset.product_id, key=key, exclude_id=preset.id)
    preset.key = key
    preset.value_type = value_type
    preset.default_value = parse_value(value_type, default_raw)
    db.add(Event(
        product_id=preset.product_id, type="preset:updated",
        payload={"key": key, "value_type": value_type,
                 "scope": "product" if preset.product_id else "global"},
        note=note,
    ))
    db.commit()
    db.refresh(preset)
    return preset


def delete_presets(
    db: Session, presets: list[FeaturePreset], *,
    note: str = "service/preset-delete",
) -> int:
    """Delete N presets in one transaction. Existing licenses are untouched —
    presets are authoring templates, not live references; keys already
    inserted into a license's features JSON stay there. Commits."""
    for p in presets:
        db.add(Event(
            product_id=p.product_id, type="preset:deleted",
            payload={"key": p.key, "scope": "product" if p.product_id else "global"},
            note=note,
        ))
        db.delete(p)
    db.commit()
    return len(presets)
