"""v1.4.0 / v1.4.1 — admin visibility for dead webhook push-channels.

A license with a webhook_url but NO webhook_secret has a silently-dead push
channel: webhooks.deliver_* short-circuits on the missing secret, so the admin
sees a green "On" with no hint that nothing is being delivered. Surface it:
- the admin product-detail list shows a "No secret" warning badge (not "On");
- the JSON list endpoint exposes a `has_webhook_secret` boolean — never the
  secret value itself;
- the license edit modal shows an inline dead-channel warning (v1.4.1).
"""
from __future__ import annotations

import json
import re

from fastapi.testclient import TestClient


def _login(c: TestClient) -> dict[str, str]:
    r = c.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return {"ls_session": r.cookies["ls_session"]}


def _create_product(c: TestClient) -> None:
    r = c.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": "asm", "name": "ASM", "key_prefix": "asm"},
    )
    assert r.status_code == 200, r.text


def _issue(c: TestClient, **overrides) -> str:
    body = {"email": "x@example.com", "plan": "standard", "valid_days": 30, "features": {}}
    body.update(overrides)
    r = c.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json=body,
    )
    assert r.status_code == 200, r.text
    return r.json()["key"]


def _set_state(key: str, **fields) -> None:
    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        lic = s.query(License).filter_by(key=key).one()
        for k, v in fields.items():
            setattr(lic, k, v)
        s.commit()


# ---- API: has_webhook_secret boolean (never the secret itself) -----------


def test_admin_list_exposes_has_webhook_secret_not_the_secret(client: TestClient) -> None:
    _create_product(client)
    key = _issue(client)

    # No URL → no secret → flag False; raw secret never in the payload.
    r = client.get(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
    )
    item = r.json()["items"][0]
    assert item["has_webhook_secret"] is False
    assert "webhook_secret" not in item

    # URL + secret → flag flips True; still no raw secret leaked.
    _set_state(key, webhook_url="https://t.example/wh", webhook_secret="whsec_x")
    r2 = client.get(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
    )
    item2 = r2.json()["items"][0]
    assert item2["has_webhook_secret"] is True
    assert "webhook_secret" not in item2


# ---- UI: 3-state webhook column -----------------------------------------


def test_ui_dead_channel_shows_no_secret_badge(client: TestClient) -> None:
    """URL set but secret NULL → 'No secret' warning, not a green 'On'."""
    cookies = _login(client)
    _create_product(client)
    key = _issue(client)
    _set_state(key, webhook_url="https://t.example/wh", webhook_secret=None)

    r = client.get("/admin/products/asm", cookies=cookies)
    assert r.status_code == 200
    assert "No secret" in r.text
    # Must NOT also read a green "On" — the whole point is it's a dead channel.
    assert ">On<" not in r.text
    assert 'data-sort-value="1"' in r.text  # health rank: dead = 1


def test_ui_healthy_channel_shows_on_badge(client: TestClient) -> None:
    """URL + secret → green 'On', no warning."""
    cookies = _login(client)
    _create_product(client)
    key = _issue(client)
    _set_state(key, webhook_url="https://t.example/wh", webhook_secret="whsec_x")

    r = client.get("/admin/products/asm", cookies=cookies)
    assert r.status_code == 200
    assert ">On<" in r.text
    assert "No secret" not in r.text
    assert 'data-sort-value="2"' in r.text  # health rank: live = 2


def test_ui_no_url_shows_dash_not_warning(client: TestClient) -> None:
    """No webhook URL → muted dash, never the 'No secret' warning."""
    cookies = _login(client)
    _create_product(client)
    _issue(client)

    r = client.get("/admin/products/asm", cookies=cookies)
    assert r.status_code == 200
    assert "No secret" not in r.text
    assert 'data-sort-value="0"' in r.text  # health rank: no channel = 0


# ---- modal: inline dead-channel warning (v1.4.1) ------------------------
#
# The list badge sends operators to the edit modal ("click Update"); the modal
# must itself flag the dead channel. Show/hide is client-side JS keyed on the
# licenses-data block, so the TestClient can only assert (a) the warning element
# is wired into the modal and (b) the data the JS keys on is correct.


def _licenses_data(html: str) -> dict:
    m = re.search(
        r'<script type="application/json" id="licenses-data">\s*(\{.*?\})\s*</script>',
        html, re.DOTALL,
    )
    assert m, "licenses-data block missing"
    return json.loads(m.group(1))


def test_modal_dead_channel_warning_element_wired(client: TestClient) -> None:
    """The (JS-toggled) dead-channel warning element exists in the modal."""
    cookies = _login(client)
    _create_product(client)
    _issue(client)

    r = client.get("/admin/products/asm", cookies=cookies)
    assert r.status_code == 200
    assert 'id="lm-webhook-deadchannel"' in r.text


def test_modal_data_signals_dead_channel(client: TestClient) -> None:
    """A dead-channel license surfaces a non-empty webhook_url with an EMPTY
    webhook_secret in licenses-data — the exact condition open() shows the
    warning on."""
    cookies = _login(client)
    _create_product(client)
    key = _issue(client)
    _set_state(key, webhook_url="https://t.example/wh", webhook_secret=None)

    lic = _licenses_data(client.get("/admin/products/asm", cookies=cookies).text)["licenses"][0]
    assert lic["webhook_url"] == "https://t.example/wh"
    assert lic["webhook_secret"] == ""  # empty → JS shows the warning


def test_modal_data_healthy_channel_carries_secret(client: TestClient) -> None:
    """A healthy channel carries a secret → warning condition is false."""
    cookies = _login(client)
    _create_product(client)
    key = _issue(client)
    _set_state(key, webhook_url="https://t.example/wh", webhook_secret="whsec_x")

    lic = _licenses_data(client.get("/admin/products/asm", cookies=cookies).text)["licenses"][0]
    assert lic["webhook_url"] == "https://t.example/wh"
    assert lic["webhook_secret"] == "whsec_x"
