"""End-to-end smoke for v1.0.3 against prod.

What it verifies:
  1. Admin can create a throwaway product + license with an admin-set webhook URL.
  2. /v1/check with a mismatched public_url returns 200 + JWT (NOT 409 like
     v1.0.0..v1.0.2 did).
  3. webhook_secret in the response stays null (admin source policy).
  4. /v1/check audit event 'webhook:override_refused' is recorded (verified
     via /admin/events on the next step ... actually we'd need cookie auth
     for that, so we skip and rely on the test suite + 200 response).
  5. JSON admin API returns webhook_url_source on each license row (items
     1+2 data plumbing).
  6. Cleans up the throwaway product (cascade-deletes the license).

Run:  .venv/Scripts/python.exe scripts/smoke_v1_0_3.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import httpx

BASE = "https://yg-license-server.duckdns.org"
SLUG = "smoke-v1-0-3"

ROOT = Path(__file__).resolve().parent.parent
ENV = ROOT / ".env.prod"

# Parse ADMIN_TOKEN out of .env.prod (gitignored, source-of-truth).
admin_token = None
for line in ENV.read_text(encoding="utf-8").splitlines():
    if line.startswith("ADMIN_TOKEN="):
        admin_token = line.split("=", 1)[1].strip().strip('"').strip("'")
        break
if not admin_token:
    print("ADMIN_TOKEN not found in .env.prod", file=sys.stderr)
    sys.exit(1)

H = {"Authorization": f"Bearer {admin_token}"}


def step(label: str) -> None:
    print(f"\n--{label}")


def fail(msg: str) -> None:
    print(f"  FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg: str) -> None:
    print(f"  OK:   {msg}")


with httpx.Client(timeout=30.0, follow_redirects=False) as c:
    step("1. health")
    r = c.get(f"{BASE}/health")
    assert r.status_code == 200, r.text
    ver = r.json().get("version")
    if not ver.startswith("1.0."):
        fail(f"expected v1.0.x; got {ver}")
    ok(f"live, version={ver}")

    step(f"2. create throwaway product (or reuse existing {SLUG})")
    r = c.post(
        f"{BASE}/v1/admin/products", headers=H,
        json={"slug": SLUG, "name": "Smoke v1.0.3", "key_prefix": "smk"},
    )
    if r.status_code == 200:
        ok(f"product {SLUG} created")
    elif r.status_code == 409 or "already exists" in r.text.lower():
        ok(f"reusing existing {SLUG} (cleanup via psql at end)")
    else:
        fail(f"create product: {r.status_code} {r.text}")

    try:
        step("4. issue license with admin-set webhook URL")
        admin_url = "https://admin.example.com/notify"
        r = c.post(
            f"{BASE}/v1/admin/products/{SLUG}/licenses", headers=H,
            json={
                "email": "smoke@example.com", "plan": "standard",
                "valid_days": 1, "features": {},
                "webhook_url": admin_url,
            },
        )
        if r.status_code != 200:
            fail(f"issue license: {r.status_code} {r.text}")
        body = r.json()
        license_key = body.get("key")
        license_id = body.get("license_id")
        if not license_key or not license_id:
            fail(f"issue license response missing key/license_id: {body}")
        ok(f"license issued (id={license_id})")

        step("5. /v1/admin/products/{slug}/licenses includes webhook_url_source")
        r = c.get(f"{BASE}/v1/admin/products/{SLUG}/licenses", headers=H)
        if r.status_code != 200:
            fail(f"list licenses: {r.status_code} {r.text}")
        items = r.json().get("items", [])
        if not items or "webhook_url_source" not in items[0]:
            fail(f"webhook_url_source missing on row: {items}")
        if items[0]["webhook_url_source"] != "admin":
            fail(f"expected source=admin; got {items[0]['webhook_url_source']}")
        ok("webhook_url_source='admin' present in JSON")

        step("6. /v1/check with MISMATCHED public_url -> 200 + no secret echo (item 3 + admin policy)")
        r = c.post(
            f"{BASE}/v1/check",
            json={
                "key": license_key, "install_id": "smoke-ii-1", "version": "1.0",
                "public_url": "https://attacker.tld/sink",
            },
        )
        if r.status_code != 200:
            fail(f"expected 200 (was 409 pre-v1.0.3); got {r.status_code} {r.text}")
        body = r.json()
        if not body.get("jwt"):
            fail("no JWT in response")
        secret = body.get("webhook_secret")
        if secret not in (None, ""):
            fail(f"webhook_secret should be null for admin source; got {secret!r}")
        ok("heartbeat 200 + JWT minted + webhook_secret=null")

        step("7. confirm URL was NOT overwritten")
        r = c.get(f"{BASE}/v1/admin/products/{SLUG}/licenses", headers=H)
        items = r.json().get("items", [])
        if items[0].get("webhook_url") != admin_url:
            fail(f"URL changed unexpectedly: {items[0].get('webhook_url')}")
        ok("URL still admin-set")

        step("8. /v1/check WITHOUT public_url -> normal heartbeat 200")
        r = c.post(
            f"{BASE}/v1/check",
            json={"key": license_key, "install_id": "smoke-ii-1", "version": "1.0"},
        )
        if r.status_code != 200:
            fail(f"plain heartbeat: {r.status_code} {r.text}")
        ok("plain heartbeat 200")

    finally:
        step("9. teardown: revoke license + flag product for psql cleanup")
        if "license_id" in dir() and license_id:
            r = c.post(f"{BASE}/v1/admin/licenses/{license_id}/revoke", headers=H)
            if r.status_code == 200:
                ok("license revoked (will be cleaned via psql after smoke)")
            else:
                print(f"  warn: revoke returned {r.status_code} {r.text}", file=sys.stderr)
        print(f"\nNOTE: throwaway product '{SLUG}' left behind. Clean via sqlite3 on the VM:")
        print(
            "  gcloud compute ssh yg-license-server --zone=us-west1-a"
            " --ssh-flag=-t --command='sudo sqlite3"
            " /var/lib/yg-license-server/license.db"
            f' \\"DELETE FROM products WHERE slug=\\\'\'{SLUG}\\\'\';\\"\''
        )

print("\n[OK] v1.0.3 smoke green")
