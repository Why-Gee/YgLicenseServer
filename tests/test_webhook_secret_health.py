"""v1.4.0 / v1.4.1 — admin visibility for dead webhook push-channels.

A license with a webhook_url but NO webhook_secret has a silently-dead push
channel: webhooks.deliver_* short-circuits on the missing secret, so the admin
sees a green "On" with no hint that nothing is being delivered. Surface it:
- the admin product-detail list shows a "No secret" warning badge (not "On");
- the JSON list endpoint exposes a `has_webhook_secret` boolean — never the
  secret value itself;
- the license edit modal shows an inline dead-channel warning (v1.4.1).

v1.4.2 hardening: the licenses-data block no longer emits the raw signing secret
for every license. It carries a `has_webhook_secret` boolean for all rows and the
real secret value ONLY for the single just-set/rotated row the server flagged via
?webhook_lid / ?issued (reveal_lid). Everything else gets an empty string.
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


def _get_secret(key: str) -> str | None:
    from app.db import SessionLocal
    from app.models import License
    with SessionLocal() as s:
        return s.query(License).filter_by(key=key).one().webhook_secret


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
    """A dead-channel license surfaces a non-empty webhook_url with
    has_webhook_secret False — the exact condition open() shows the warning on
    (the JS toggle keys on has_webhook_secret, not the raw value)."""
    cookies = _login(client)
    _create_product(client)
    key = _issue(client)
    _set_state(key, webhook_url="https://t.example/wh", webhook_secret=None)

    lic = _licenses_data(client.get("/admin/products/asm", cookies=cookies).text)["licenses"][0]
    assert lic["webhook_url"] == "https://t.example/wh"
    assert lic["has_webhook_secret"] is False  # → JS shows the warning
    assert lic["webhook_secret"] == ""


def test_modal_data_healthy_channel_hides_secret_when_not_revealed(client: TestClient) -> None:
    """A healthy channel signals presence via has_webhook_secret=True but must
    NOT carry the raw secret in the data block on an ordinary render (no reveal
    param). The value only appears on the just-set/rotated reveal row."""
    cookies = _login(client)
    _create_product(client)
    key = _issue(client)
    _set_state(key, webhook_url="https://t.example/wh", webhook_secret="whsec_x")

    lic = _licenses_data(client.get("/admin/products/asm", cookies=cookies).text)["licenses"][0]
    assert lic["webhook_url"] == "https://t.example/wh"
    assert lic["has_webhook_secret"] is True  # warning condition is false
    assert lic["webhook_secret"] == ""  # NOT leaked on an ordinary render


def test_modal_secret_revealed_only_for_its_reveal_row(client: TestClient) -> None:
    """The raw secret is emitted for exactly the row flagged by ?webhook_lid
    (so the modal can show it once after set/rotate) — never for any other row."""
    cookies = _login(client)
    _create_product(client)
    k_a = _issue(client, email="a@example.com")
    k_b = _issue(client, email="b@example.com")
    _set_state(k_a, webhook_url="https://t.example/a", webhook_secret="whsec_AAA")
    _set_state(k_b, webhook_url="https://t.example/b", webhook_secret="whsec_BBB")

    # No reveal param → neither raw secret is in the data; presence flags True.
    data = _licenses_data(client.get("/admin/products/asm", cookies=cookies).text)
    by_email = {lic["email"]: lic for lic in data["licenses"]}
    assert by_email["a@example.com"]["webhook_secret"] == ""
    assert by_email["b@example.com"]["webhook_secret"] == ""
    assert by_email["a@example.com"]["has_webhook_secret"] is True
    assert by_email["b@example.com"]["has_webhook_secret"] is True

    # Reveal license A only → A carries its secret, B stays hidden.
    lid_a = by_email["a@example.com"]["id"]
    html = client.get(f"/admin/products/asm?webhook_lid={lid_a}", cookies=cookies).text
    by_email2 = {lic["email"]: lic for lic in _licenses_data(html)["licenses"]}
    assert by_email2["a@example.com"]["webhook_secret"] == "whsec_AAA"
    assert by_email2["b@example.com"]["webhook_secret"] == ""  # not the reveal row
    assert "whsec_BBB" not in html  # other rows' secrets never appear in the page


def test_modal_secret_revealed_for_issued_param_freshly_minted(client: TestClient) -> None:
    """First-ever secret display path: issuing a license WITH a webhook_url mints
    a secret at issuance and the post-issue redirect carries ?issued=<lid>. That
    row's freshly-minted secret must be revealed in licenses-data — and only that
    row's. ?issued and ?webhook_lid feed the same reveal_lid, but this pins the
    issuance source directly (the only path a brand-new secret reaches the page)."""
    cookies = _login(client)
    _create_product(client)
    _issue(client, email="fresh@example.com", webhook_url="https://t.example/fresh")
    k_other = _issue(client, email="other@example.com", webhook_url="https://t.example/other")
    other_secret = _get_secret(k_other)
    assert other_secret and other_secret.startswith("whsec_")  # minted at issuance

    # No reveal param → neither minted secret is in the data; presence flags True.
    base = _licenses_data(client.get("/admin/products/asm", cookies=cookies).text)
    by_email = {lic["email"]: lic for lic in base["licenses"]}
    assert by_email["fresh@example.com"]["has_webhook_secret"] is True
    assert by_email["fresh@example.com"]["webhook_secret"] == ""
    lid_fresh = by_email["fresh@example.com"]["id"]

    # Simulate the post-issue redirect → fresh row reveals its minted secret only.
    html = client.get(f"/admin/products/asm?issued={lid_fresh}", cookies=cookies).text
    by_email2 = {lic["email"]: lic for lic in _licenses_data(html)["licenses"]}
    revealed = by_email2["fresh@example.com"]["webhook_secret"]
    assert revealed.startswith("whsec_") and len(revealed) > 10
    assert by_email2["other@example.com"]["webhook_secret"] == ""  # not the reveal row
    assert other_secret not in html  # the other issued row's secret never leaks


def test_raw_secret_never_in_page_source_without_reveal(client: TestClient) -> None:
    """Canary: with no reveal param, a license's raw signing secret must not
    appear anywhere in the rendered page source."""
    cookies = _login(client)
    _create_product(client)
    key = _issue(client)
    _set_state(key, webhook_url="https://t.example/wh", webhook_secret="whsec_CANARY_LEAK")

    html = client.get("/admin/products/asm", cookies=cookies).text
    assert "whsec_CANARY_LEAK" not in html


# ---- deliveries page: Configured-receivers health badge (v1.4.3) ---------
#
# The webhook-deliveries page lists every license with a webhook_url under
# "Configured receivers". A receiver whose license has no webhook_secret is a
# silently-dead channel (deliver_* short-circuits), so the row must carry the
# same On / "No secret" health signal as the product-detail list — server
# rendered, so it's the boolean condition only and never the secret value.


def test_deliveries_dead_channel_shows_no_secret_badge(client: TestClient) -> None:
    """A configured receiver with no secret → 'No secret' warning, not 'On'."""
    cookies = _login(client)
    _create_product(client)
    key = _issue(client)
    _set_state(key, webhook_url="https://t.example/wh", webhook_secret=None)

    r = client.get("/admin/webhook-deliveries", cookies=cookies)
    assert r.status_code == 200
    assert "No secret" in r.text
    assert ">On<" not in r.text


def test_deliveries_healthy_channel_shows_on_badge(client: TestClient) -> None:
    """A configured receiver with a secret → green 'On', no warning."""
    cookies = _login(client)
    _create_product(client)
    key = _issue(client)
    _set_state(key, webhook_url="https://t.example/wh", webhook_secret="whsec_x")

    r = client.get("/admin/webhook-deliveries", cookies=cookies)
    assert r.status_code == 200
    assert ">On<" in r.text
    assert "No secret" not in r.text


def test_deliveries_configured_receiver_never_leaks_secret(client: TestClient) -> None:
    """The badge is a boolean condition — the raw secret value must never reach
    the deliveries page source."""
    cookies = _login(client)
    _create_product(client)
    key = _issue(client)
    _set_state(key, webhook_url="https://t.example/wh", webhook_secret="whsec_DELIV_CANARY")

    r = client.get("/admin/webhook-deliveries", cookies=cookies)
    assert "whsec_DELIV_CANARY" not in r.text
    # Positive pin too: the badge must actually render (a regression that dropped
    # the whole Push cell would pass an absence-only check).
    assert ">On<" in r.text
