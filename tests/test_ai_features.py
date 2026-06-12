"""First-class AI feature keys (`ai_api_included`, `ai_included_usd_cap`).

Consumed by ASM's license-bundled AI auto-provisioning: ASM gates its
"platform AI key" path on features.ai_api_included and reads
features.ai_included_usd_cap as the default monthly USD allowance.

Pins:
1. Issued JWT + /v1/check body carry both keys.
2. Renewal (stripe invoice.paid extension) preserves them.
3. Toggle-off authoring emits explicit ai_api_included: false.
4. Dedicated fields win over hand-typed features JSON.
5. Cap validation: positive finite number, only alongside the toggle.
"""
from __future__ import annotations

import re
from urllib.parse import unquote

import jwt as jwt_lib
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


def _create_product(client: TestClient, slug: str = "asm") -> None:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": slug, "name": "ASM", "key_prefix": slug},
    )
    assert r.status_code == 200, r.text


def _issue_api(client: TestClient, slug: str = "asm", **overrides) -> dict:
    body = {"email": "x@example.com", "plan": "standard", "valid_days": 30}
    body.update(overrides)
    r = client.post(
        f"/v1/admin/products/{slug}/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json=body,
    )
    return r


def _read_features(key: str) -> dict:
    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        return dict(s.query(License).filter_by(key=key).one().features or {})


def _check(client: TestClient, key: str) -> dict:
    r = client.post("/v1/check", json={"key": key, "install_id": "i1", "version": "1.0.0"})
    assert r.status_code == 200, r.text
    return r.json()


def _decode(client: TestClient, token: str, slug: str = "asm") -> dict:
    pub = client.get(f"/v1/products/{slug}/pubkey").text
    return jwt_lib.decode(
        token, pub, algorithms=["EdDSA"], audience=slug, options={"verify_exp": False}
    )


# ----- unit: apply_ai_features / parse_usd_cap ----------------------------


def test_apply_ai_features_explicit_false_and_cap_removal() -> None:
    from app.services.licenses import apply_ai_features
    feats = {"ai_api_included": True, "ai_included_usd_cap": 25, "other": 1}
    out = apply_ai_features(feats, ai_api_included=False, ai_included_usd_cap=None)
    assert out["ai_api_included"] is False          # explicit, not removed
    assert "ai_included_usd_cap" not in out         # cap dropped with toggle
    assert out["other"] == 1                        # unrelated keys untouched


def test_apply_ai_features_writes_cap_only_when_included() -> None:
    from app.services.errors import ValidationFailed
    from app.services.licenses import apply_ai_features
    out = apply_ai_features({}, ai_api_included=True, ai_included_usd_cap=12.5)
    assert out == {"ai_api_included": True, "ai_included_usd_cap": 12.5}
    # no cap -> key absent (empty = no cap), toggle still explicit
    out2 = apply_ai_features({}, ai_api_included=True, ai_included_usd_cap=None)
    assert out2 == {"ai_api_included": True}
    with pytest.raises(ValidationFailed):
        apply_ai_features({}, ai_api_included=False, ai_included_usd_cap=10)


@pytest.mark.parametrize("bad", [0, -5, float("inf"), float("nan")])
def test_apply_ai_features_rejects_non_positive_or_non_finite_cap(bad: float) -> None:
    from app.services.errors import ValidationFailed
    from app.services.licenses import apply_ai_features
    with pytest.raises(ValidationFailed):
        apply_ai_features({}, ai_api_included=True, ai_included_usd_cap=bad)


def test_parse_usd_cap() -> None:
    from app.services.errors import ValidationFailed
    from app.services.licenses import parse_usd_cap
    assert parse_usd_cap("") is None
    assert parse_usd_cap("   ") is None
    assert parse_usd_cap("12.5") == 12.5
    with pytest.raises(ValidationFailed):
        parse_usd_cap("abc")


# ----- JSON API ------------------------------------------------------------


def test_api_issue_with_ai_keys_lands_in_jwt(client: TestClient) -> None:
    _create_product(client)
    r = _issue_api(client, ai_api_included=True, ai_included_usd_cap=20)
    assert r.status_code == 200, r.text
    key = r.json()["key"]

    body = _check(client, key)
    assert body["features"]["ai_api_included"] is True
    assert body["features"]["ai_included_usd_cap"] == 20

    claims = _decode(client, body["jwt"])
    assert claims["features"]["ai_api_included"] is True
    assert claims["features"]["ai_included_usd_cap"] == 20


def test_api_issue_toggle_false_emits_explicit_false(client: TestClient) -> None:
    _create_product(client)
    r = _issue_api(client, ai_api_included=False)
    assert r.status_code == 200, r.text
    feats = _read_features(r.json()["key"])
    assert feats["ai_api_included"] is False
    assert "ai_included_usd_cap" not in feats


def test_api_issue_without_ai_params_leaves_features_verbatim(client: TestClient) -> None:
    """Back-compat: callers that author `features` directly see no injected keys."""
    _create_product(client)
    r = _issue_api(client, features={"chat_agent": True})
    assert r.status_code == 200, r.text
    assert _read_features(r.json()["key"]) == {"chat_agent": True}


def test_api_issue_cap_without_toggle_400s(client: TestClient) -> None:
    _create_product(client)
    r = _issue_api(client, ai_api_included=False, ai_included_usd_cap=10)
    assert r.status_code == 400
    # cap alone (toggle unstated) is equally a misuse, and must not
    # half-create a customer row either
    r2 = _issue_api(client, ai_included_usd_cap=10)
    assert r2.status_code == 400
    from app.db import SessionLocal
    from app.models import Customer
    with SessionLocal() as s:
        assert s.query(Customer).count() == 0


def test_api_issue_rejects_non_positive_cap(client: TestClient) -> None:
    _create_product(client)
    assert _issue_api(client, ai_api_included=True, ai_included_usd_cap=0).status_code == 400
    assert _issue_api(client, ai_api_included=True, ai_included_usd_cap=-3).status_code == 400


def test_api_first_class_fields_override_features_json(client: TestClient) -> None:
    _create_product(client)
    r = _issue_api(
        client,
        features={"ai_api_included": True, "ai_included_usd_cap": 99, "other": "x"},
        ai_api_included=False,
    )
    assert r.status_code == 200, r.text
    feats = _read_features(r.json()["key"])
    assert feats == {"ai_api_included": False, "other": "x"}


# ----- admin UI form -------------------------------------------------------


def _issue_ui(client: TestClient, cookies: dict[str, str], data_extra: dict) -> str:
    data = {
        "email": "ui@example.com", "plan": "standard", "max_users": "10",
        "valid_days": "30", "features_json": "{}",
        "csrf_token": _csrf(cookies),
    }
    data.update(data_extra)
    r = client.post(
        "/admin/products/asm/licenses", data=data,
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    loc = r.headers["location"]
    assert "error=" not in loc, loc
    m = re.search(r"key=([^&]+)", loc)
    assert m, loc
    return unquote(m.group(1))


def test_ui_issue_toggle_on_with_cap(client: TestClient) -> None:
    _create_product(client)
    cookies = _login(client)
    key = _issue_ui(client, cookies, {"ai_api_included": "1", "ai_included_usd_cap": "15.50"})
    assert _read_features(key) == {"ai_api_included": True, "ai_included_usd_cap": 15.5}


def test_ui_issue_toggle_off_emits_explicit_false(client: TestClient) -> None:
    """Unchecked checkbox = field absent from the POST = explicit false."""
    _create_product(client)
    cookies = _login(client)
    key = _issue_ui(client, cookies, {})
    feats = _read_features(key)
    assert feats["ai_api_included"] is False
    assert "ai_included_usd_cap" not in feats


def test_ui_issue_toggle_overrides_features_json(client: TestClient) -> None:
    """Dedicated controls are authoritative over hand-typed JSON."""
    _create_product(client)
    cookies = _login(client)
    key = _issue_ui(client, cookies, {
        "features_json": '{"ai_api_included": true, "ai_included_usd_cap": 99, "keep": 1}',
    })
    assert _read_features(key) == {"ai_api_included": False, "keep": 1}


def test_ui_issue_invalid_cap_redirects_with_error(client: TestClient) -> None:
    _create_product(client)
    cookies = _login(client)
    r = client.post(
        "/admin/products/asm/licenses",
        data={
            "email": "ui@example.com", "plan": "standard", "max_users": "10",
            "valid_days": "30", "features_json": "{}",
            "ai_api_included": "1", "ai_included_usd_cap": "lots",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert "error=invalid+ai+usd+cap" in r.headers["location"]


def test_ui_edit_toggle_off_clears_cap_and_writes_false(client: TestClient) -> None:
    """Edit form without the checkbox un-sets AI: explicit false + cap removed."""
    _create_product(client)
    r = _issue_api(client, ai_api_included=True, ai_included_usd_cap=30)
    key = r.json()["key"]
    lid = r.json()["license_id"]

    cookies = _login(client)
    r2 = client.post(
        f"/admin/licenses/{lid}/edit",
        data={
            "plan": "standard", "max_users": "10",
            "valid_until": "2030-01-01", "features_json": "{}",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r2.status_code == 303, r2.text
    assert "error=" not in r2.headers["location"]
    feats = _read_features(key)
    assert feats["ai_api_included"] is False
    assert "ai_included_usd_cap" not in feats
    # and the next JWT reflects it
    claims = _decode(client, _check(client, key)["jwt"])
    assert claims["features"]["ai_api_included"] is False


def test_ui_edit_toggle_on_adds_keys(client: TestClient) -> None:
    _create_product(client)
    r = _issue_api(client, features={"chat_agent": True})
    key = r.json()["key"]
    lid = r.json()["license_id"]

    cookies = _login(client)
    r2 = client.post(
        f"/admin/licenses/{lid}/edit",
        data={
            "plan": "standard", "max_users": "10",
            "valid_until": "2030-01-01",
            "features_json": '{"chat_agent": true}',
            "ai_api_included": "1", "ai_included_usd_cap": "40",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r2.status_code == 303, r2.text
    assert "error=" not in r2.headers["location"]
    assert _read_features(key) == {
        "chat_agent": True, "ai_api_included": True, "ai_included_usd_cap": 40.0,
    }


# ----- renewal preserves ----------------------------------------------------


def test_stripe_renewal_extension_preserves_ai_features(client: TestClient) -> None:
    """invoice.paid extends valid_until on the existing row; features —
    including the AI keys — must survive, and the re-minted JWT must still
    carry them."""
    _create_product(client)
    r = _issue_api(
        client, ai_api_included=True, ai_included_usd_cap=20,
        stripe_customer_id="cus_123",
    )
    key = r.json()["key"]
    before = _check(client, key)["valid_until"]

    from app.db import SessionLocal
    from app.models import Product
    from app.stripe_webhook import _extend_or_create
    with SessionLocal() as s:
        product = s.query(Product).filter_by(slug="asm").one()
        _extend_or_create(s, product=product, customer_id="cus_123", email="x@example.com")
        s.commit()

    after = _check(client, key)
    assert after["valid_until"] > before                      # actually extended
    assert after["features"]["ai_api_included"] is True       # preserved
    assert after["features"]["ai_included_usd_cap"] == 20
    claims = _decode(client, after["jwt"])
    assert claims["features"]["ai_api_included"] is True
    assert claims["features"]["ai_included_usd_cap"] == 20
