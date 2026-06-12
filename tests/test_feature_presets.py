"""Feature presets (v1.2.0) + LS product-agnosticism pins.

Presets are admin-defined authoring templates for license `features` keys —
pure typo-safety; LS attaches no semantics to any key. These tests pin:

1. Preset CRUD (global + per-product scopes, uniqueness per scope).
2. Shape validation (key format, value-matches-type) and error redirects.
3. The license modal data embeds presets for the product page.
4. LS agnosticism: the v1.1.0 first-class ai_* API fields are GONE — unknown
   body fields are ignored and `features` passes through verbatim.
5. Renewal (stripe invoice.paid extension) preserves features untouched.
6. Product deletion cascades its presets; globals survive.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

# ----- helpers -----------------------------------------------------------


def _login(client: TestClient) -> dict[str, str]:
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return {"ls_session": r.cookies["ls_session"]}


def _csrf(cookies: dict[str, str]) -> str:
    from app.config import get_settings
    from app.security import csrf_token
    return csrf_token(get_settings().session_secret, cookies["ls_session"])


def _create_product(client: TestClient, slug: str = "asm") -> str:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": slug, "name": slug.upper(), "key_prefix": slug},
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _create_preset(
    client: TestClient, cookies: dict[str, str], *,
    product_id: str = "", key: str = "premium", value_type: str = "bool",
    default_value: str = "true",
):
    return client.post(
        "/admin/presets",
        data={
            "product_id": product_id, "key": key, "value_type": value_type,
            "default_value": default_value, "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )


def _all_presets():
    from app.db import SessionLocal
    from app.models import FeaturePreset
    with SessionLocal() as s:
        return [
            (p.product_id, p.key, p.value_type, p.default_value)
            for p in s.query(FeaturePreset).all()
        ]


# ----- unit: parse_value ---------------------------------------------------


def test_parse_value_types() -> None:
    from app.services.presets import parse_value
    assert parse_value("bool", "true") is True
    assert parse_value("bool", "FALSE") is False
    assert parse_value("number", "25") == 25
    assert parse_value("number", "12.5") == 12.5
    assert parse_value("string", "hello world") == "hello world"
    assert parse_value("json", '{"tier": "gold"}') == {"tier": "gold"}
    assert parse_value("json", "[1, 2]") == [1, 2]


@pytest.mark.parametrize(("vt", "raw"), [
    ("bool", "maybe"),
    ("number", "abc"),
    ("number", "true"),       # bool is not a number
    ("number", "Infinity"),
    ("json", "{not json"),
    ("nope", "true"),         # unknown type
])
def test_parse_value_rejects(vt: str, raw: str) -> None:
    from app.services.errors import ValidationFailed
    from app.services.presets import parse_value
    with pytest.raises(ValidationFailed):
        parse_value(vt, raw)


# ----- CRUD via UI routes ---------------------------------------------------


def test_create_global_and_product_preset(client: TestClient) -> None:
    pid = _create_product(client)
    cookies = _login(client)
    r1 = _create_preset(client, cookies, key="premium", value_type="bool", default_value="true")
    assert r1.status_code == 303 and "created=1" in r1.headers["location"]
    r2 = _create_preset(
        client, cookies, product_id=pid,
        key="ai_included_usd_cap", value_type="number", default_value="25",
    )
    assert r2.status_code == 303 and "created=1" in r2.headers["location"]
    rows = _all_presets()
    assert (None, "premium", "bool", True) in rows
    assert (pid, "ai_included_usd_cap", "number", 25) in rows


def test_duplicate_key_same_scope_rejected_distinct_scope_ok(client: TestClient) -> None:
    pid = _create_product(client)
    cookies = _login(client)
    assert "created=1" in _create_preset(client, cookies, key="premium").headers["location"]
    # same key, same (global) scope -> conflict
    r = _create_preset(client, cookies, key="premium")
    assert "error=preset+exists" in r.headers["location"]
    # same key, product scope -> fine (product preset shadows nothing; both exist)
    r2 = _create_preset(client, cookies, product_id=pid, key="premium")
    assert "created=1" in r2.headers["location"]
    assert len(_all_presets()) == 2


@pytest.mark.parametrize(("field", "value", "code"), [
    ("key", "bad key!", "invalid+preset+key"),
    ("key", "", "invalid+preset+key"),
    ("value_type", "float", "invalid+preset+type"),
    ("default_value", "not-a-number", "invalid+preset+value"),
])
def test_create_validation_errors(client: TestClient, field: str, value: str, code: str) -> None:
    _create_product(client)
    cookies = _login(client)
    data = {"key": "ok_key", "value_type": "number", "default_value": "5"}
    data[field] = value
    r = client.post(
        "/admin/presets",
        data={**data, "product_id": "", "csrf_token": _csrf(cookies)},
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert f"error={code}" in r.headers["location"], r.headers["location"]
    assert _all_presets() == []


def test_edit_preset(client: TestClient) -> None:
    _create_product(client)
    cookies = _login(client)
    _create_preset(client, cookies, key="premium", value_type="bool", default_value="true")
    from app.db import SessionLocal
    from app.models import FeaturePreset
    with SessionLocal() as s:
        pid = s.query(FeaturePreset).one().id
    r = client.post(
        f"/admin/presets/{pid}/edit",
        data={
            "key": "premium_support", "value_type": "string",
            "default_value": "gold", "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303 and "edited=1" in r.headers["location"]
    assert _all_presets() == [(None, "premium_support", "string", "gold")]


def test_delete_single_and_bulk(client: TestClient) -> None:
    _create_product(client)
    cookies = _login(client)
    for k in ("a_key", "b_key", "c_key"):
        _create_preset(client, cookies, key=k)
    from app.db import SessionLocal
    from app.models import FeaturePreset
    with SessionLocal() as s:
        ids = [p.id for p in s.query(FeaturePreset).order_by(FeaturePreset.key).all()]
    # single (trash icon path)
    r = client.post(
        f"/admin/presets/{ids[0]}/delete",
        data={"csrf_token": _csrf(cookies)},
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303 and "deleted=1" in r.headers["location"]
    # bulk
    r2 = client.post(
        "/admin/presets/delete",
        data={"preset_ids": ids[1:], "csrf_token": _csrf(cookies)},
        cookies=cookies, follow_redirects=False,
    )
    assert r2.status_code == 303 and "deleted=2" in r2.headers["location"]
    assert _all_presets() == []
    # bulk with nothing selected -> friendly error
    r3 = client.post(
        "/admin/presets/delete",
        data={"csrf_token": _csrf(cookies)},
        cookies=cookies, follow_redirects=False,
    )
    assert "error=no+presets+selected" in r3.headers["location"]


def test_presets_page_renders(client: TestClient) -> None:
    _create_product(client)
    cookies = _login(client)
    _create_preset(client, cookies, key="premium_support")
    r = client.get("/admin/presets", cookies=cookies)
    assert r.status_code == 200
    assert "premium_support" in r.text


def test_product_page_embeds_presets(client: TestClient) -> None:
    """License modal needs global + this product's presets; another
    product's presets must NOT leak in."""
    pid = _create_product(client, slug="asm")
    _create_product(client, slug="other")
    cookies = _login(client)
    _create_preset(client, cookies, key="global_key")
    _create_preset(client, cookies, product_id=pid, key="asm_key")
    r = client.get("/admin/products/other", cookies=cookies)
    assert r.status_code == 200
    assert "global_key" in r.text
    assert "asm_key" not in r.text


def test_product_delete_cascades_its_presets(client: TestClient) -> None:
    pid = _create_product(client, slug="asm")
    cookies = _login(client)
    _create_preset(client, cookies, key="global_key")
    _create_preset(client, cookies, product_id=pid, key="asm_key")
    r = client.post(
        "/admin/products/asm/delete",
        data={"csrf_token": _csrf(cookies)},
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    rows = _all_presets()
    assert rows == [(None, "global_key", "bool", True)]


# ----- LS agnosticism pins ---------------------------------------------------


def test_api_ignores_legacy_ai_fields_and_passes_features_verbatim(client: TestClient) -> None:
    """v1.1.0's first-class ai_* fields are gone: LS no longer interprets
    ANY features key. Unknown body fields are ignored; the features dict is
    stored exactly as sent (including consumer-specific keys)."""
    _create_product(client)
    r = client.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={
            "email": "x@example.com", "valid_days": 30,
            "features": {"ai_api_included": True, "ai_included_usd_cap": 20},
            # legacy v1.1.0 top-level fields -- must be ignored, not merged
            "ai_api_included": False,
            "ai_included_usd_cap": 999,
        },
    )
    assert r.status_code == 200, r.text
    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        feats = s.query(License).one().features
    assert feats == {"ai_api_included": True, "ai_included_usd_cap": 20}


def test_stripe_renewal_extension_preserves_features(client: TestClient) -> None:
    """invoice.paid extends valid_until on the existing row; the opaque
    features dict must survive untouched and the re-minted JWT must carry it."""
    import jwt as jwt_lib
    _create_product(client)
    r = client.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={
            "email": "x@example.com", "valid_days": 30,
            "features": {"ai_api_included": True, "ai_included_usd_cap": 20},
            "stripe_customer_id": "cus_123",
        },
    )
    assert r.status_code == 200, r.text
    key = r.json()["key"]

    def check() -> dict:
        rc = client.post("/v1/check", json={"key": key, "install_id": "i1", "version": "1.0.0"})
        assert rc.status_code == 200, rc.text
        return rc.json()

    before = check()["valid_until"]

    from app.db import SessionLocal
    from app.models import Product
    from app.stripe_webhook import _extend_or_create
    with SessionLocal() as s:
        product = s.query(Product).filter_by(slug="asm").one()
        _extend_or_create(s, product=product, customer_id="cus_123", email="x@example.com")
        s.commit()

    after = check()
    assert after["valid_until"] > before
    assert after["features"] == {"ai_api_included": True, "ai_included_usd_cap": 20}
    pub = client.get("/v1/products/asm/pubkey").text
    claims = jwt_lib.decode(
        after["jwt"], pub, algorithms=["EdDSA"], audience="asm",
        options={"verify_exp": False},
    )
    assert claims["features"] == {"ai_api_included": True, "ai_included_usd_cap": 20}
