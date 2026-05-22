"""Phase 1 security hardening — TDD tests for vulns 1-3 + H4.

Each test exercises one specific fix and is added BEFORE the fix is
implemented (red-green-refactor).
"""
from __future__ import annotations

import csv
import io
import socket
from contextlib import contextmanager

import httpx
import pytest
from fastapi.testclient import TestClient


@contextmanager
def _captured(monkeypatch, status: int = 200):
    sent: list[dict] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        sent.append({
            "url": str(req.url),
            "headers": dict(req.headers),
            "body": req.content.decode() if req.content else "",
        })
        return httpx.Response(status, content=b'{"ok":true}')

    test_client = httpx.Client(
        transport=httpx.MockTransport(_handler), follow_redirects=False,
    )
    import app.http_client as hc
    monkeypatch.setattr(hc, "_client", test_client)
    try:
        yield sent
    finally:
        test_client.close()


def _admin_login(client: TestClient) -> dict[str, str]:
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return {"ls_session": r.cookies["ls_session"]}


def _csrf_for(cookies: dict[str, str]) -> str:
    from app.config import get_settings
    from app.security import csrf_token
    return csrf_token(get_settings().session_secret, cookies["ls_session"])


def _form_post(client: TestClient, url: str, cookies: dict[str, str], data: dict | None = None, **kw):
    payload = dict(data or {})
    payload.setdefault("csrf_token", _csrf_for(cookies))
    return client.post(url, data=payload, cookies=cookies, **kw)


def _create_product(client: TestClient, slug: str = "asm") -> None:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": slug, "name": slug.upper(), "key_prefix": slug},
    )
    assert r.status_code == 200, r.text


def _issue_and_get_key(
    client: TestClient, slug: str = "asm", data: dict | None = None
) -> str:
    """Issue a license via the admin UI form and return the plaintext key
    from the ?key= redirect param (v1.0: admin listing only shows key_display)."""
    cookies = _admin_login(client)
    payload: dict = {
        "email": "alice@example.com", "plan": "standard",
        "max_users": "10", "valid_days": "30", "features_json": "{}",
    }
    if data:
        payload.update(data)
    r = _form_post(
        client, f"/admin/products/{slug}/licenses", cookies,
        data=payload, follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    loc = r.headers["location"]
    from urllib.parse import parse_qs, urlparse
    qs = parse_qs(urlparse(loc).query)
    key = qs.get("key", [None])[0]
    assert key, f"no key= in redirect: {loc}"
    return key


def _issue_with_webhook(client: TestClient, slug: str, webhook_url: str) -> str:
    """Issue a license via the admin UI form so we can set a webhook URL.
    Returns the license id."""
    cookies = _admin_login(client)
    r = _form_post(
        client, f"/admin/products/{slug}/licenses", cookies,
        data={
            "email": "alice@example.com",
            "plan": "standard",
            "max_users": "10",
            "valid_days": "30",
            "features_json": "{}",
            "webhook_url": webhook_url,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    # Parse the redirect for the issued license id.
    loc = r.headers["location"]
    assert "issued=" in loc, loc
    return loc.split("issued=")[1].split("&")[0]


# ---------- DNS stub fixture -----------------------------------------------
# resolve_safe_address resolves DNS before building the pinned URL.  Test
# hostnames like *.example.com may not resolve in CI, so return a routable
# public IP for any .example.com hostname.  Per-test overrides (monkeypatch
# inside the test body) take precedence because they run after this fixture.

_REAL_GETADDRINFO = socket.getaddrinfo


def _stub_getaddrinfo(host, port, *args, **kwargs):
    if isinstance(host, str) and host.endswith(".example.com"):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", port or 0))]
    return _REAL_GETADDRINFO(host, port, *args, **kwargs)


@pytest.fixture(autouse=True)
def _patch_dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _stub_getaddrinfo)


# ---------- H4: _fire_deleted_webhook --------------------------------------


def test_delete_product_fires_webhooks_without_crashing(client, monkeypatch):
    """delete_product with a webhook-configured license must NOT raise
    ImportError on _fire_deleted_webhook (currently a latent crash) AND
    must deliver one license.deleted webhook per license."""
    _create_product(client)
    with _captured(monkeypatch) as sent:
        _issue_with_webhook(client, "asm", "https://customer.example.com/webhook")
        cookies = _admin_login(client)
        # delete the product → cascade-deletes the license → should fire webhook.
        r = _form_post(
            client, "/admin/products/asm/delete", cookies, follow_redirects=False,
        )
        assert r.status_code == 303, r.text
    deleted = [s for s in sent if "license.deleted" in s["headers"].get("x-license-server-event", "")]
    assert len(deleted) == 1, f"expected 1 license.deleted webhook, got {sent}"

    from app.db import SessionLocal
    from app.models import WebhookDelivery
    with SessionLocal() as s:
        deliveries = s.query(WebhookDelivery).all()
        deleted_rows = [d for d in deliveries if d.event_type == "license.deleted"]
        assert len(deleted_rows) == 1, (
            f"expected exactly one WebhookDelivery row for license.deleted, "
            f"got {len(deleted_rows)}: {[(d.id, d.event_type) for d in deliveries]}"
        )


# ---------- Vuln 3: CSV injection ------------------------------------------


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "=cmd|'/c calc'!A0",
        "+1+1",
        "-2+3",
        "@SUM(1+1)",
        "\t=danger",
        "\rdanger",
    ],
)
def test_customers_csv_neutralises_formula_chars(client, unsafe_value):
    """Customer name/email starting with formula characters must be prefixed
    with a single apostrophe so spreadsheets render them as literal text."""
    _create_product(client)
    # Issue a license with the dangerous name to seed a customer.
    r = client.post(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
        json={
            "email": "alice@example.com", "name": unsafe_value,
            "plan": "standard", "valid_days": 30,
        },
    )
    assert r.status_code == 200, r.text
    r = client.get(
        "/v1/admin/exports/customers.csv",
        headers={"Authorization": "Bearer test-admin"},
    )
    assert r.status_code == 200
    rows = list(csv.reader(io.StringIO(r.text)))
    # Header + 1 row.
    assert len(rows) >= 2
    name_idx = rows[0].index("name")
    name_cell = rows[1][name_idx]
    # The service layer strips leading/trailing whitespace before storing, so
    # \t/\r prefixes are removed upstream; the stored value may differ from
    # unsafe_value. Two valid outcomes:
    #   1. The stored value retained an unsafe prefix → cell must start with "'".
    #   2. The stored value had the unsafe prefix stripped → cell is safe as-is.
    # In neither case should a bare unsafe character appear as the first char.
    if name_cell and name_cell[0] in ("=", "+", "-", "@", "\t", "\r"):
        pytest.fail(f"unsanitised name cell in customers.csv: {name_cell!r}")
    # If the guard fired (cell starts with "'"), verify the payload is intact.
    if name_cell.startswith("'"):
        payload = name_cell[1:]
        # The payload must equal either the raw input or its stripped variant.
        assert payload == unsafe_value or payload == unsafe_value.strip(), (
            f"apostrophe-prefixed payload unexpected: {payload!r} for input {unsafe_value!r}"
        )


def test_events_csv_neutralises_formula_chars(client):
    """Admin UI events.csv must apply the same guard."""
    _create_product(client)
    # Issue a license with a dangerous note — flows through the issued event.
    cookies = _admin_login(client)
    _ = _form_post(
        client, "/admin/products/asm/licenses", cookies,
        data={
            "email": "bob@example.com",
            "plan": "=evil",  # plan is admin-controlled, but exercises the path
            "max_users": "10",
            "valid_days": "30",
            "features_json": "{}",
        },
        follow_redirects=False,
    )
    r = client.get("/admin/events.csv", cookies=cookies, follow_redirects=False)
    assert r.status_code == 200
    rows = list(csv.reader(io.StringIO(r.text)))
    # find any cell starting with one of the unsafe chars (unprefixed)
    for row in rows[1:]:
        for cell in row:
            if cell and cell[0] in ("=", "+", "-", "@", "\t", "\r"):
                pytest.fail(f"unsanitised cell escaped into events.csv: {cell!r}")


# ---------- Vuln 2: DNS-rebinding bypass -----------------------------------


def test_webhook_delivery_pins_resolved_ip(client, monkeypatch):
    """Mock getaddrinfo to return one IP, then assert httpx receives a
    request whose URL host is that IP (not the original hostname) and whose
    Host header carries the original hostname. Proves the deliver path
    resolves once and connects by IP, defeating DNS-rebinding."""
    # Capture what getaddrinfo says for the receiver hostname.
    real_getaddrinfo = socket.getaddrinfo

    # 93.184.216.34 = example.com; not in any private/reserved range per
    # Python's ipaddress module (unlike RFC-5737 TEST-NET-3 203.0.113.0/24
    # which is_private=True in Python 3.11+).
    def _fake_getaddrinfo(host, port, *args, **kwargs):
        if host == "customer.example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", port or 0))]
        return real_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

    _create_product(client)
    with _captured(monkeypatch) as sent:
        lid = _issue_with_webhook(client, "asm", "https://customer.example.com/wh")
        cookies = _admin_login(client)
        # disable → fires a status-change webhook
        r = _form_post(
            client, f"/admin/licenses/{lid}/disable", cookies, follow_redirects=False,
        )
        assert r.status_code == 303
    assert sent, "no webhook fired"
    req = sent[-1]
    # URL must contain the pinned IP, not the hostname.
    assert "93.184.216.34" in req["url"], f"request url did not use pinned IP: {req['url']}"
    assert "customer.example.com" not in req["url"], (
        f"hostname leaked into url; DNS-rebind window still open: {req['url']}"
    )
    # Host header must still be the original hostname so the receiver
    # virtual-hosts correctly and TLS SNI matches the cert.
    assert req["headers"].get("host") == "customer.example.com", req["headers"]


# ---------- Vuln 1: webhook hijack + secret leak ---------------------------


def test_v1check_does_not_overwrite_admin_set_webhook_url(client):
    """A license-key holder calling /v1/check with public_url must NOT
    silently overwrite a webhook_url set by the admin."""
    _create_product(client)
    # Issue via UI form + capture plaintext key from the ?key= redirect param.
    key = _issue_and_get_key(
        client, data={"webhook_url": "https://admin.example.com/notify"}
    )
    # Now an attacker holding the key tries to redirect the webhook.
    r = client.post(
        "/v1/check",
        json={
            "key": key, "install_id": "ii-1", "version": "1.0",
            "public_url": "https://attacker.tld/sink",
        },
    )
    # The response must be a refusal (409 — locked) OR a 200 with the URL
    # unchanged. The spec picks 409 for clarity.
    assert r.status_code == 409, r.text
    # Re-fetch the license; URL must still be the admin one.
    r = client.get(
        "/v1/admin/products/asm/licenses",
        headers={"Authorization": "Bearer test-admin"},
    )
    items = r.json()["items"]
    assert items[0].get("webhook_url") == "https://admin.example.com/notify"


def test_v1check_secret_not_returned_when_admin_set(client):
    """When the webhook URL was set by the admin, /v1/check must NOT
    include webhook_secret in the response — only the original receiver
    (the customer's HTTP receiver) should have learned the secret, via
    the one-time-display in the admin UI."""
    _create_product(client)
    key = _issue_and_get_key(
        client, data={"webhook_url": "https://customer.example.com/wh"}
    )
    r = client.post(
        "/v1/check",
        json={"key": key, "install_id": "ii-1", "version": "1.0"},
    )
    assert r.status_code == 200, r.text
    assert r.json().get("webhook_secret") in (None, "")


def test_v1check_self_registered_flow_still_works(client):
    """A license issued WITHOUT a webhook can still self-register via
    /v1/check; secret is returned so the customer's app can verify
    incoming webhooks."""
    _create_product(client)
    key = _issue_and_get_key(client)
    r = client.post(
        "/v1/check",
        json={
            "key": key, "install_id": "ii-1", "version": "1.0",
            "public_url": "https://customer.example.com/wh",
        },
    )
    assert r.status_code == 200, r.text
    assert r.json().get("webhook_secret"), r.json()


def test_v1check_does_not_mint_secret_when_no_url(client):
    """A license with no webhook URL must NOT receive a lazy-minted secret
    on /v1/check; the secret only exists alongside a real URL."""
    _create_product(client)
    key = _issue_and_get_key(client)
    r = client.post(
        "/v1/check",
        json={"key": key, "install_id": "ii-1", "version": "1.0"},
    )
    assert r.status_code == 200
    # No URL -> no secret in response.
    assert r.json().get("webhook_secret") in (None, "")


def test_webhook_refused_when_dns_resolves_only_to_private(client, monkeypatch):
    """If every A/AAAA the hostname returns is private/loopback/link-local,
    deliver must refuse before opening any socket."""
    real_getaddrinfo = socket.getaddrinfo

    def _fake_getaddrinfo(host, port, *args, **kwargs):
        if host == "bad.example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", port or 0))]
        return real_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

    _create_product(client)
    with _captured(monkeypatch) as sent:
        lid = _issue_with_webhook(client, "asm", "https://bad.example.com/wh")
        cookies = _admin_login(client)
        r = _form_post(
            client, f"/admin/licenses/{lid}/disable", cookies, follow_redirects=False,
        )
        assert r.status_code == 303
    assert not sent, f"webhook fired despite link-local DNS: {sent}"
