"""UI license-issuance UX:
1. Plaintext key shows ONLY inside the auto-opened modal (Key field), not in
   a parent-page banner hidden under the overlay.
2. Issuance via the admin UI dispatches the customer email (send_email=True
   on the service call) — JSON API has always done this, UI was forgetting.

Smoke-tested as part of v1.0.x patch series."""
from __future__ import annotations

import json
import re
from contextlib import contextmanager

import httpx
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


def _issue_via_ui(
    client: TestClient, cookies: dict[str, str], *, slug: str = "asm",
    email: str = "buyer@example.com",
) -> tuple[str, str]:
    """POST to the UI issue endpoint, follow no redirect; return (license_id, key)
    parsed from the redirect location."""
    r = client.post(
        f"/admin/products/{slug}/licenses",
        data={
            "email": email, "plan": "standard", "max_users": "10",
            "valid_days": "30", "features_json": "{}",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    loc = r.headers["location"]
    m_lid = re.search(r"issued=([^&]+)", loc)
    m_key = re.search(r"key=([^&]+)", loc)
    assert m_lid and m_key, f"redirect missing issued/key: {loc}"
    from urllib.parse import unquote
    return m_lid.group(1), unquote(m_key.group(1))


@contextmanager
def _captured_resend(monkeypatch, status: int = 200):
    sent: list[dict] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        sent.append({
            "url": str(req.url),
            "body": json.loads(req.content.decode()) if req.content else {},
        })
        return httpx.Response(status, content=b'{"id":"e_test"}')

    tc = httpx.Client(transport=httpx.MockTransport(_handler), follow_redirects=False)
    import app.http_client as hc
    monkeypatch.setattr(hc, "_client", tc)
    try:
        yield sent
    finally:
        tc.close()


# ----- 1. parent banner gone, key lives inside modal --------------------


def test_parent_banner_with_plaintext_key_is_gone(client: TestClient) -> None:
    """After issuance, the listing page must NOT render a top-of-page
    success banner containing the plaintext key — the previous flow showed
    that banner hidden under the auto-opened modal, which is unusable."""
    cookies = _login(client)
    _create_product(client)
    lid, key = _issue_via_ui(client, cookies)

    r = client.get(
        f"/admin/products/asm?issued={lid}&key={key}",
        cookies=cookies,
    )
    assert r.status_code == 200
    body = r.text

    # The plaintext key must NOT appear inside a top-level success div. The
    # previous template wrapped it in `<div class="success" ...><pre ...>KEY</pre>`.
    # Pin the pre-tag form to avoid false positives on the inner-modal JSON.
    assert '<pre style="margin:.5em 0;' not in body, (
        "parent-page success banner with plaintext key is still rendered"
    )
    # And the leading copy from that banner must be gone too.
    assert "copy this key now — it is not shown again" not in body


def test_modal_key_field_carries_plaintext_after_issuance(client: TestClient) -> None:
    """The licenses-data JSON block must carry the plaintext key so the
    modal JS can show it in the Key row with a Copy button."""
    cookies = _login(client)
    _create_product(client)
    lid, key = _issue_via_ui(client, cookies)

    r = client.get(
        f"/admin/products/asm?issued={lid}&key={key}",
        cookies=cookies,
    )
    assert r.status_code == 200
    # Extract the JSON inside <script type="application/json" id="licenses-data">.
    m = re.search(
        r'<script type="application/json" id="licenses-data">\s*(\{.*?\})\s*</script>',
        r.text, re.DOTALL,
    )
    assert m, "licenses-data JSON block missing"
    data = json.loads(m.group(1))
    assert data["issued_key"] == key, (
        f"issued_key must equal posted plaintext; got {data.get('issued_key')!r}"
    )


def test_no_issued_key_when_query_absent(client: TestClient) -> None:
    """A plain GET (no ?issued/?key) must zero-out issued_key so the modal
    JS never reveals stale plaintext on a regular page load."""
    cookies = _login(client)
    _create_product(client)
    _issue_via_ui(client, cookies)

    r = client.get("/admin/products/asm", cookies=cookies)
    assert r.status_code == 200
    m = re.search(
        r'<script type="application/json" id="licenses-data">\s*(\{.*?\})\s*</script>',
        r.text, re.DOTALL,
    )
    assert m
    data = json.loads(m.group(1))
    assert data["issued_key"] == "", (
        "issued_key must be empty on a non-issuance render"
    )


# ----- 2. UI issuance dispatches the customer email ---------------------


def test_ui_issue_dispatches_resend_email(make_client, monkeypatch) -> None:
    """Issuance via the admin UI form must hit Resend exactly once with the
    plaintext key in the body — JSON API has always done this; UI was
    silently passing send_email=False."""
    c = make_client(RESEND_API_KEY="re_test_key", EMAIL_FROM="onboarding@resend.dev")
    cookies = _login(c)
    _create_product(c)

    with _captured_resend(monkeypatch) as sent:
        _, key = _issue_via_ui(c, cookies, email="ui-buyer@example.com")

    assert len(sent) == 1, f"expected one Resend POST from UI issue, got {len(sent)}"
    msg = sent[0]
    assert msg["url"] == "https://api.resend.com/emails"
    assert msg["body"]["to"] == ["ui-buyer@example.com"]
    assert key in msg["body"]["text"]
