# Product Create + Edit Modal — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unify product create + edit into a single modal on `/admin/products`, replacing the standalone `/admin/products/new` page and adding an in-place edit path.

**Architecture:** New `update_product` service in `app/services/products.py`. New `POST /admin/products/{slug}/edit` route. The existing `+ New Product` link becomes a modal trigger; a pencil-icon per row triggers edit mode of the same modal. The `/admin/products/new` GET route + `product_new.html` template are deleted.

**Tech Stack:** FastAPI, SQLAlchemy, Jinja2, vanilla JS.

**Spec:** [docs/superpowers/specs/2026-05-20-product-edit-design.md](../specs/2026-05-20-product-edit-design.md)

---

## File Structure

| File | Change |
|---|---|
| `app/services/products.py` | **Modify** — add `update_product()` |
| `app/routers/admin_ui/products.py` | **Modify** — add `product_edit`, delete `product_new_form`, change `product_create` error redirect target + enable `validate_format=True` |
| `app/templates/products.html` | **Modify** — replace href button with modal trigger, add edit pencil per row, add modal markup + JSON payload + JS, add `?product_edited=` banner |
| `app/templates/product_new.html` | **Delete** |
| `app/__init__.py` | **Modify** — version `0.17.0` → `0.18.0` |
| `tests/test_product_edit.py` | **Create** |
| `tests/test_ui_v07.py` | **Modify** — update line 85 assertion |

---

## Task 1: Service — `update_product`

**Files:**
- Modify: `app/services/products.py`
- Test: `tests/test_product_edit.py` (new)

- [ ] **Step 1: Write the failing service tests**

Create `tests/test_product_edit.py`:

```python
"""Product edit service + router tests (v0.18.0)."""
from __future__ import annotations

import app.db as db_mod
from app.models import Event, Product
from app.services import products as products_svc
from app.services.errors import Conflict, ValidationFailed
from fastapi.testclient import TestClient
import pytest


# ------------------------- service-level tests ----------------------------

def _seed_product(slug: str = "myapp", name: str = "My App", key_prefix: str = "myapp"):
    with db_mod.SessionLocal() as db:
        return products_svc.create_product(
            db, slug=slug, name=name, key_prefix=key_prefix,
        )


def test_update_product_changes_name_and_description(client: TestClient) -> None:
    _seed_product()
    with db_mod.SessionLocal() as db:
        products_svc.update_product(
            db, "myapp", name="New Name", description="hello",
        )
        p = db.query(Product).filter_by(slug="myapp").one()
        assert p.name == "New Name"
        assert p.description == "hello"
        ev = db.query(Event).filter_by(type="product:edited").one()
        assert ev.payload["slug"] == "myapp"
        assert ev.payload["changes"] == {
            "name": ["My App", "New Name"],
            "description": [None, "hello"],
        }


def test_update_product_renames_slug(client: TestClient) -> None:
    _seed_product()
    with db_mod.SessionLocal() as db:
        products_svc.update_product(db, "myapp", new_slug="renamed")
        assert db.query(Product).filter_by(slug="renamed").one_or_none() is not None
        assert db.query(Product).filter_by(slug="myapp").one_or_none() is None


def test_update_product_changes_key_prefix(client: TestClient) -> None:
    _seed_product()
    with db_mod.SessionLocal() as db:
        products_svc.update_product(db, "myapp", key_prefix="newpfx")
        p = db.query(Product).filter_by(slug="myapp").one()
        assert p.key_prefix == "newpfx"


def test_update_product_changes_jwt_issuer(client: TestClient) -> None:
    _seed_product()
    with db_mod.SessionLocal() as db:
        products_svc.update_product(db, "myapp", jwt_issuer="custom-iss")
        p = db.query(Product).filter_by(slug="myapp").one()
        assert p.jwt_issuer == "custom-iss"


def test_update_product_rejects_slug_collision(client: TestClient) -> None:
    _seed_product(slug="a", name="A", key_prefix="a")
    _seed_product(slug="b", name="B", key_prefix="b")
    with db_mod.SessionLocal() as db, pytest.raises(Conflict):
        products_svc.update_product(db, "a", new_slug="b")


def test_update_product_rejects_invalid_slug(client: TestClient) -> None:
    _seed_product()
    with db_mod.SessionLocal() as db, pytest.raises(ValidationFailed):
        products_svc.update_product(db, "myapp", new_slug="Bad Slug!")


def test_update_product_rejects_invalid_key_prefix(client: TestClient) -> None:
    _seed_product()
    with db_mod.SessionLocal() as db, pytest.raises(ValidationFailed):
        products_svc.update_product(db, "myapp", key_prefix="BAD-PFX")


def test_update_product_missing_slug_raises(client: TestClient) -> None:
    from app.services.errors import NotFound
    with db_mod.SessionLocal() as db, pytest.raises(NotFound):
        products_svc.update_product(db, "nope", name="x")


def test_update_product_noop_writes_no_event(client: TestClient) -> None:
    _seed_product()
    with db_mod.SessionLocal() as db:
        n_before = db.query(Event).filter_by(type="product:edited").count()
        products_svc.update_product(db, "myapp")  # nothing to change
        n_after = db.query(Event).filter_by(type="product:edited").count()
        assert n_before == n_after
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/test_product_edit.py -v`
Expected: All tests FAIL with `AttributeError: module 'app.services.products' has no attribute 'update_product'`.

- [ ] **Step 3: Implement `update_product`**

In `app/services/products.py`, append after `delete_product`:

```python
def update_product(
    db: Session,
    slug: str,
    *,
    new_slug: str | None = None,
    name: str | None = None,
    key_prefix: str | None = None,
    jwt_issuer: str | None = None,
    description: str | None = None,
) -> Product:
    """Edit an existing product. Each kwarg = None leaves that field unchanged.

    Validates the slug + key_prefix regexes. Rejects a slug rename that would
    collide with another product. Writes a `product:edited` Event whose
    payload diff records only the fields that actually changed; no-op edits
    write no event. Single commit.
    """
    p = db.query(Product).filter_by(slug=slug).one_or_none()
    if p is None:
        raise NotFound("product not found")

    if new_slug is not None and new_slug != p.slug:
        if not _SLUG_RE.match(new_slug):
            raise ValidationFailed("invalid slug (lowercase a-z0-9-, max 63)")
        if db.query(Product).filter_by(slug=new_slug).one_or_none() is not None:
            raise Conflict("slug already exists")
    if key_prefix is not None and key_prefix != p.key_prefix:
        if not _PREFIX_RE.match(key_prefix):
            raise ValidationFailed("invalid key_prefix (lowercase a-z0-9_, max 15)")

    # Build the diff before mutating so we record old->new per changed field.
    candidates = {
        "slug": new_slug,
        "name": name,
        "key_prefix": key_prefix,
        "jwt_issuer": jwt_issuer,
        "description": description,
    }
    changes: dict[str, list] = {}
    for field, new_val in candidates.items():
        if new_val is None:
            continue
        old_val = getattr(p, field)
        if new_val != old_val:
            changes[field] = [old_val, new_val]

    if not changes:
        return p  # idempotent submit; no event noise

    for field, (_, new_val) in changes.items():
        setattr(p, field, new_val)

    db.add(Event(
        product_id=p.id,
        type="product:edited",
        payload={"slug": slug, "changes": changes},
    ))
    db.commit()
    db.refresh(p)
    return p
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_product_edit.py -v`
Expected: All 9 service tests PASS.

- [ ] **Step 5: Commit**

```bash
git add app/services/products.py tests/test_product_edit.py
git commit -m "feat(products): add update_product service"
```

---

## Task 2: Router — `POST /admin/products/{slug}/edit`

**Files:**
- Modify: `app/routers/admin_ui/products.py`
- Modify: `tests/test_product_edit.py`

- [ ] **Step 1: Write the failing router tests**

Append to `tests/test_product_edit.py`:

```python
# ------------------------- router-level tests -----------------------------

def _login(client: TestClient) -> dict[str, str]:
    r = client.post("/admin/login", data={"token": "test-admin"}, follow_redirects=False)
    assert r.status_code == 303
    return {"ls_session": r.cookies["ls_session"]}


def _csrf(cookies: dict[str, str]) -> str:
    from app.config import get_settings
    from app.security import csrf_token
    return csrf_token(get_settings().session_secret, cookies["ls_session"])


def _admin_create(client: TestClient, slug: str = "myapp") -> None:
    r = client.post(
        "/v1/admin/products",
        headers={"Authorization": "Bearer test-admin"},
        json={"slug": slug, "name": slug.upper(), "key_prefix": slug},
    )
    assert r.status_code == 200, r.text


def test_edit_route_requires_csrf(client: TestClient) -> None:
    _admin_create(client)
    cookies = _login(client)
    r = client.post(
        "/admin/products/myapp/edit",
        data={"name": "x"},
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 403


def test_edit_route_requires_login(client: TestClient) -> None:
    _admin_create(client)
    r = client.post(
        "/admin/products/myapp/edit",
        data={"name": "x", "csrf_token": "irrelevant"},
        follow_redirects=False,
    )
    # LoginRequired handler emits a 303 to /admin/login.
    assert r.status_code == 303
    assert r.headers["location"].startswith("/admin/login")


def test_edit_route_missing_product_404(client: TestClient) -> None:
    cookies = _login(client)
    r = client.post(
        "/admin/products/nope/edit",
        data={"name": "x", "csrf_token": _csrf(cookies)},
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 404


def test_edit_route_success_redirects_with_product_edited(client: TestClient) -> None:
    _admin_create(client)
    cookies = _login(client)
    r = client.post(
        "/admin/products/myapp/edit",
        data={
            "slug": "myapp", "name": "Renamed",
            "key_prefix": "myapp", "jwt_issuer": "",
            "description": "",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/admin/products?product_edited=myapp"


def test_edit_route_renames_slug_in_redirect(client: TestClient) -> None:
    _admin_create(client, slug="orig")
    cookies = _login(client)
    r = client.post(
        "/admin/products/orig/edit",
        data={
            "slug": "renamed", "name": "ORIG",
            "key_prefix": "orig", "jwt_issuer": "",
            "description": "",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/admin/products?product_edited=renamed"


def test_edit_route_slug_collision_redirects_with_error(client: TestClient) -> None:
    _admin_create(client, slug="a")
    _admin_create(client, slug="b")
    cookies = _login(client)
    r = client.post(
        "/admin/products/a/edit",
        data={
            "slug": "b", "name": "A",
            "key_prefix": "a", "jwt_issuer": "",
            "description": "",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/admin/products?error=slug+exists"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/test_product_edit.py -v -k "route"`
Expected: All 6 router tests FAIL with `404 Not Found` (route doesn't exist yet).

- [ ] **Step 3: Implement `product_edit` route**

In `app/routers/admin_ui/products.py`, after the `product_create` handler, add:

```python
@router.post("/admin/products/{slug}/edit")
def product_edit(
    slug: str,
    request: Request,
    new_slug: str = Form("", alias="slug"),
    name: str = Form(""),
    key_prefix: str = Form(""),
    jwt_issuer: str = Form(""),
    description: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Edit an existing product via the unified create/edit modal.

    The form's `slug` field is the desired new slug; the path slug is the
    current slug we're editing. None-values are normalized so blank optional
    fields don't overwrite stored values with empty strings.
    """
    require_login(request)
    require_csrf(request, csrf_token)
    try:
        p = products_svc.update_product(
            db, slug,
            new_slug=new_slug or None,
            name=name or None,
            key_prefix=key_prefix or None,
            jwt_issuer=jwt_issuer or None,
            description=description if description != "" else None,
        )
    except NotFound as e:
        raise HTTPException(status_code=404) from e
    except Conflict as e:
        return RedirectResponse(f"/admin/products?error={err_code(e)}", status_code=303)
    except ValidationFailed as e:
        return RedirectResponse(f"/admin/products?error={err_code(e)}", status_code=303)
    return RedirectResponse(
        f"/admin/products?product_edited={p.slug}", status_code=303,
    )
```

Also update imports at the top of `app/routers/admin_ui/products.py`:

```python
from app.services.errors import Conflict, NotFound, ValidationFailed
```

(Adds `ValidationFailed` to the existing import.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_product_edit.py -v`
Expected: All 15 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add app/routers/admin_ui/products.py tests/test_product_edit.py
git commit -m "feat(products): POST /admin/products/{slug}/edit"
```

---

## Task 3: Router cleanup — delete `/admin/products/new` + retarget create error

**Files:**
- Modify: `app/routers/admin_ui/products.py`
- Modify: `tests/test_ui_v07.py:85`
- Modify: `tests/test_product_edit.py`

- [ ] **Step 1: Write tests for the new behavior**

Append to `tests/test_product_edit.py`:

```python
def test_new_product_route_is_gone(client: TestClient) -> None:
    """The standalone /admin/products/new page is replaced by the modal."""
    cookies = _login(client)
    r = client.get("/admin/products/new", cookies=cookies)
    assert r.status_code == 404


def test_create_collision_redirects_to_products_list(client: TestClient) -> None:
    """Create-error redirect target moved from /admin/products/new to /admin/products."""
    _admin_create(client, slug="dup")
    cookies = _login(client)
    r = client.post(
        "/admin/products",
        data={
            "slug": "dup", "name": "Dup",
            "key_prefix": "dup",
            "csrf_token": _csrf(cookies),
        },
        cookies=cookies, follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/admin/products?error=slug+exists"
```

Update the assertion in `tests/test_ui_v07.py:85` from:

```python
    # New-product button still on this page.
    assert b'href="/admin/products/new"' in r.content
```

to:

```python
    # New-product button is now a modal trigger (was href="/admin/products/new").
    assert b'data-product-modal="create"' in r.content
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/test_product_edit.py tests/test_ui_v07.py -v`
Expected:
- `test_new_product_route_is_gone` FAILS (returns 200; the route still exists)
- `test_create_collision_redirects_to_products_list` FAILS (redirects to `/admin/products/new?...`)
- `test_products_tab_lists_products` FAILS (assertion looks for `data-product-modal="create"` which isn't there yet)

- [ ] **Step 3: Update the router**

In `app/routers/admin_ui/products.py`:

1. **Delete** the entire `product_new_form` handler (the `@router.get("/admin/products/new", ...)` block + its function body).

2. **Modify** `product_create` to:
   - Redirect on `Conflict` to `/admin/products?error=...` instead of `/admin/products/new?error=...`.
   - Also catch `ValidationFailed` (new — was previously possible to skip because `validate_format=False` was the default).
   - Pass `validate_format=True` to `create_product` (defensive — modal validates client-side, but a hand-crafted POST shouldn't bypass).

Replace `product_create` with:

```python
@router.post("/admin/products")
def product_create(
    request: Request,
    slug: str = Form(...),
    name: str = Form(...),
    key_prefix: str = Form(...),
    description: str = Form(""),
    jwt_issuer: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    require_login(request)
    require_csrf(request, csrf_token)
    try:
        products_svc.create_product(
            db, slug=slug, name=name, key_prefix=key_prefix,
            description=description or None,
            jwt_issuer=jwt_issuer or None,
            validate_format=True,
        )
    except (Conflict, ValidationFailed) as e:
        return RedirectResponse(
            f"/admin/products?error={err_code(e)}", status_code=303,
        )
    return RedirectResponse(f"/admin/products/{slug}", status_code=303)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_product_edit.py tests/test_ui_v07.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add app/routers/admin_ui/products.py tests/test_product_edit.py tests/test_ui_v07.py
git commit -m "refactor(products): drop /admin/products/new page; retarget create errors to list"
```

---

## Task 4: Template — unified product modal on `products.html`

**Files:**
- Modify: `app/templates/products.html`

This is a single large template edit. After this task, the products page shows the modal trigger + edit pencils, the modal markup is present, and inline JS wires it all up.

- [ ] **Step 1: Add the `product_edited` success banner**

In `app/templates/products.html`, locate the existing flash blocks (around line 6-16). Insert a new banner *immediately after* the `deleted_products` block, before the `_err` block:

```jinja
{% if request.query_params.get('product_edited') %}
<div class="success">product '{{ request.query_params.get('product_edited') }}' updated.</div>
{% endif %}
```

- [ ] **Step 2: Replace the `+ New Product` link with a modal trigger**

Find this line:

```html
<a class="btn" href="/admin/products/new">+ New Product</a>
```

Replace with:

```html
<button type="button" class="btn" data-product-modal="create">+ New Product</button>
```

- [ ] **Step 3: Add the edit pencil button to each product row**

In the row's actions cell (currently contains only the trash button), prepend the edit pencil. Replace the existing `<td>` containing the trash button with:

```jinja
<td style="white-space:nowrap;">
  <button type="button" class="btn-icon"
          data-product-modal="edit"
          data-product-slug="{{ p.slug }}"
          title="Edit this product"
          aria-label="Edit this product">
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M12.146.146a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1 0 .708l-10 10a.5.5 0 0 1-.168.11l-5 2a.5.5 0 0 1-.65-.65l2-5a.5.5 0 0 1 .11-.168zM11.207 2.5 13.5 4.793 14.793 3.5 12.5 1.207zm1.586 3L10.5 3.207 4 9.707V10h.5a.5.5 0 0 1 .5.5v.5h.5a.5.5 0 0 1 .5.5v.5h.293zm-9.761 5.175-.106.106-1.528 3.821 3.821-1.528.106-.106A.5.5 0 0 1 5 12.5V12h-.5a.5.5 0 0 1-.5-.5V11h-.5a.5.5 0 0 1-.468-.325"/>
    </svg>
  </button>
  <button type="submit" class="btn-icon"
          formaction="/admin/products/{{ p.slug }}/delete"
          formnovalidate
          title="Delete this product"
          aria-label="Delete this product"
          data-confirm-title="Delete this product?"
          data-confirm-body="Permanently removes the product and ALL licenses + installs under it. The Ed25519 keypair is destroyed forever — clients with the old pubkey baked in will reject any future license you issue under a re-created product of the same slug. Cannot be undone."
          data-confirm-label="Delete">
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M6.5 1h3a.5.5 0 0 1 .5.5v1H6v-1a.5.5 0 0 1 .5-.5zM11 2.5v-1A1.5 1.5 0 0 0 9.5 0h-3A1.5 1.5 0 0 0 5 1.5v1H1.5a.5.5 0 0 0 0 1h.538l.853 10.66A2 2 0 0 0 4.885 16h6.23a2 2 0 0 0 1.994-1.84l.853-10.66h.538a.5.5 0 0 0 0-1H11zM4.5 5.5a.5.5 0 0 1 .5.5v8a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 0a.5.5 0 0 1 .5.5v8a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3.5.5a.5.5 0 0 0-1 0v8a.5.5 0 0 0 1 0V6z"/>
    </svg>
  </button>
</td>
```

Also fix the table header — the existing `<th style="width:1%;"></th>` for the actions column. Update to widen for two icons:

```html
<th style="width:1%;white-space:nowrap;"></th>
```

- [ ] **Step 4: Append the JSON payload + modal markup + JS at the end of the content block**

Add the following block just before `{% endblock %}` at the bottom of `products.html`:

```jinja
{# Per-product JSON payload consumed by the modal JS to pre-fill edit mode. #}
<script type="application/json" id="products-data">
{
  "products": [
    {% for p in products %}
    {
      "slug": {{ p.slug|tojson }},
      "name": {{ p.name|tojson }},
      "key_prefix": {{ p.key_prefix|tojson }},
      "jwt_issuer": {{ p.jwt_issuer|tojson }},
      "description": {{ (p.description or '')|tojson }}
    }{% if not loop.last %},{% endif %}
    {% endfor %}
  ]
}
</script>

{# Unified Product modal — create + edit in one form. #}
<div id="product-modal" class="modal-overlay" style="display:none" role="dialog" aria-modal="true" aria-labelledby="pm-title">
  <div class="modal-card" style="max-width:600px;position:relative;">
    <button type="button" id="pm-close" class="btn-icon"
            style="position:absolute;top:.5em;right:.5em;color:var(--muted);"
            title="Close" aria-label="Close">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
        <path d="M2.146 2.854a.5.5 0 1 1 .708-.708L8 7.293l5.146-5.147a.5.5 0 0 1 .708.708L8.707 8l5.147 5.146a.5.5 0 0 1-.708.708L8 8.707l-5.146 5.147a.5.5 0 0 1-.708-.708L7.293 8z"/>
      </svg>
    </button>
    <h3 id="pm-title" style="margin-top:0;">New Product</h3>
    <p id="pm-create-blurb" class="muted" style="margin-top:0;display:none;">
      creating a product generates a fresh ed25519 keypair. private key stays in the database; public key gets baked into the client app's image.
    </p>
    <form id="pm-form" method="post" style="display:grid;gap:.5em;">
      {{ csrf_input(request) }}
      <div>
        <label for="pm-slug">Slug</label>
        <input id="pm-slug" name="slug" required pattern="[a-z0-9][a-z0-9-]{0,62}" placeholder="myapp">
        <small id="pm-slug-create" class="muted">lowercase, a–z 0–9 –, max 63. URL-safe.</small>
        <small id="pm-slug-edit" class="muted" style="display:none;">renaming changes admin URLs + Stripe webhook path — update any external integrations that point at the old slug.</small>
      </div>
      <div>
        <label for="pm-name">Display Name</label>
        <input id="pm-name" name="name" required placeholder="My Application">
      </div>
      <div>
        <label for="pm-key-prefix">License-Key Prefix</label>
        <input id="pm-key-prefix" name="key_prefix" required pattern="[a-z0-9_]{1,15}" placeholder="myapp">
        <small id="pm-prefix-create" class="muted">keys for this product look like <code>myapp_aB7…</code>. lowercase a–z 0–9 _, max 15.</small>
        <small id="pm-prefix-edit" class="muted" style="display:none;">only affects keys issued from now on. existing keys keep their original prefix and continue to validate.</small>
      </div>
      <div>
        <label for="pm-jwt-issuer">JWT Issuer <span class="muted" style="font-weight:normal;font-size:.85em;">(Optional)</span></label>
        <input id="pm-jwt-issuer" name="jwt_issuer" placeholder="myapp-license-server">
        <small id="pm-issuer-create" class="muted">defaults to <code>&lt;slug&gt;-license-server</code>.</small>
        <small id="pm-issuer-edit" class="muted" style="display:none;">only affects JWTs issued from now on. clients pick up the new <code>iss</code> at next phone-home.</small>
      </div>
      <div>
        <label for="pm-description">Description <span class="muted" style="font-weight:normal;font-size:.85em;">(Optional)</span></label>
        <textarea id="pm-description" name="description" rows="3"></textarea>
      </div>
      <div class="modal-actions" style="margin-top:.4em;">
        <button type="button" class="btn muted" id="pm-cancel">Cancel</button>
        <button type="submit" id="pm-submit" class="btn">Create Product</button>
      </div>
    </form>
  </div>
</div>

{# Unsaved-changes confirm. z-index above the product modal. #}
<div id="pm-discard-confirm" class="modal-overlay" style="display:none;z-index:1100;" role="dialog" aria-modal="true" aria-labelledby="pmdc-title">
  <div class="modal-card" style="max-width:420px;">
    <h3 id="pmdc-title" style="margin-top:0;">Unsaved Changes</h3>
    <p>You have unsaved changes. Save them, discard them, or keep editing?</p>
    <div class="modal-actions">
      <button type="button" class="btn muted" id="pmdc-cancel">Cancel</button>
      <button type="button" class="btn danger" id="pmdc-discard">Discard</button>
      <button type="button" class="btn" id="pmdc-save">Save</button>
    </div>
  </div>
</div>

<script>
(function () {
  var dataEl = document.getElementById('products-data');
  if (!dataEl) return;
  var data = JSON.parse(dataEl.textContent);
  var bySlug = {};
  data.products.forEach(function (p) { bySlug[p.slug] = p; });

  var ov = document.getElementById('product-modal');
  var form = document.getElementById('pm-form');
  var titleEl = document.getElementById('pm-title');
  var blurb = document.getElementById('pm-create-blurb');
  var slugIn = document.getElementById('pm-slug');
  var nameIn = document.getElementById('pm-name');
  var prefixIn = document.getElementById('pm-key-prefix');
  var issuerIn = document.getElementById('pm-jwt-issuer');
  var descIn = document.getElementById('pm-description');
  var slugCreate = document.getElementById('pm-slug-create');
  var slugEdit = document.getElementById('pm-slug-edit');
  var prefixCreate = document.getElementById('pm-prefix-create');
  var prefixEdit = document.getElementById('pm-prefix-edit');
  var issuerCreate = document.getElementById('pm-issuer-create');
  var issuerEdit = document.getElementById('pm-issuer-edit');
  var submitBtn = document.getElementById('pm-submit');
  var cancelBtn = document.getElementById('pm-cancel');
  var closeBtn = document.getElementById('pm-close');

  var initialSnapshot = null;
  function snapshot() {
    return JSON.stringify({
      slug: slugIn.value, name: nameIn.value, prefix: prefixIn.value,
      issuer: issuerIn.value, desc: descIn.value,
    });
  }
  function isDirty() {
    return initialSnapshot !== null && snapshot() !== initialSnapshot;
  }

  function close() {
    ov.style.display = 'none';
    document.removeEventListener('keydown', onKey);
    initialSnapshot = null;
  }
  function onKey(e) { if (e.key === 'Escape') attemptClose(); }

  var dc = document.getElementById('pm-discard-confirm');
  var dcCancel = document.getElementById('pmdc-cancel');
  var dcDiscard = document.getElementById('pmdc-discard');
  var dcSave = document.getElementById('pmdc-save');
  var dcOpen = false;
  function dirtyConfirm() {
    return new Promise(function (resolve) {
      dcOpen = true;
      function done(verdict) {
        dc.style.display = 'none';
        dcOpen = false;
        dcCancel.removeEventListener('click', onCancel);
        dcDiscard.removeEventListener('click', onDiscard);
        dcSave.removeEventListener('click', onSave);
        document.removeEventListener('keydown', onDcKey);
        resolve(verdict);
      }
      function onCancel()  { done('cancel'); }
      function onDiscard() { done('discard'); }
      function onSave()    { done('save'); }
      function onDcKey(e) {
        if (e.key === 'Escape') { e.stopPropagation(); done('cancel'); }
        else if (e.key === 'Enter') { e.preventDefault(); done('save'); }
      }
      dcCancel.addEventListener('click', onCancel);
      dcDiscard.addEventListener('click', onDiscard);
      dcSave.addEventListener('click', onSave);
      document.addEventListener('keydown', onDcKey);
      dc.style.display = '';
      dcCancel.focus();
    });
  }

  async function attemptClose() {
    if (dcOpen) return;
    if (!isDirty()) { close(); return; }
    var v = await dirtyConfirm();
    if (v === 'cancel') return;
    if (v === 'discard') { close(); return; }
    if (v === 'save') {
      if (form.reportValidity()) form.submit();
    }
  }

  cancelBtn.addEventListener('click', attemptClose);
  closeBtn.addEventListener('click', attemptClose);
  ov.addEventListener('click', function (e) { if (e.target === ov) attemptClose(); });

  function open(mode, prod) {
    if (mode === 'edit') {
      titleEl.textContent = 'Edit Product';
      submitBtn.textContent = 'Save';
      blurb.style.display = 'none';
      form.action = '/admin/products/' + prod.slug + '/edit';
      slugIn.value = prod.slug;
      nameIn.value = prod.name;
      prefixIn.value = prod.key_prefix;
      issuerIn.value = prod.jwt_issuer;
      descIn.value = prod.description;
      slugCreate.style.display = 'none'; slugEdit.style.display = '';
      prefixCreate.style.display = 'none'; prefixEdit.style.display = '';
      issuerCreate.style.display = 'none'; issuerEdit.style.display = '';
    } else {
      titleEl.textContent = 'New Product';
      submitBtn.textContent = 'Create Product';
      blurb.style.display = '';
      form.action = '/admin/products';
      slugIn.value = '';
      nameIn.value = '';
      prefixIn.value = '';
      issuerIn.value = '';
      descIn.value = '';
      slugCreate.style.display = ''; slugEdit.style.display = 'none';
      prefixCreate.style.display = ''; prefixEdit.style.display = 'none';
      issuerCreate.style.display = ''; issuerEdit.style.display = 'none';
    }
    ov.style.display = '';
    document.addEventListener('keydown', onKey);
    initialSnapshot = snapshot();
    setTimeout(function () {
      (mode === 'edit' ? nameIn : slugIn).focus();
    }, 50);
  }

  document.querySelectorAll('[data-product-modal]').forEach(function (btn) {
    btn.addEventListener('click', function (e) {
      e.preventDefault();
      var mode = btn.dataset.productModal;
      if (mode === 'edit') {
        var p = bySlug[btn.dataset.productSlug];
        if (p) open('edit', p);
      } else {
        open('create', null);
      }
    });
  });

  // Strip the success flash param on reload so the banner doesn't loop.
  try {
    var u = new URL(window.location.href);
    if (u.searchParams.has('product_edited')) {
      u.searchParams.delete('product_edited');
      history.replaceState(null, '', u.pathname + (u.search ? u.search : '') + u.hash);
    }
  } catch (e) {}
})();
</script>
```

- [ ] **Step 5: Run the full test suite to verify nothing broke**

Run: `.venv/Scripts/python.exe -m pytest tests/ -x -q`
Expected: All tests PASS (168 + 11 new = 179).

- [ ] **Step 6: Manually verify the UI**

Start the dev server (`uvicorn app.main:app --reload`), log into `/admin`, navigate to `/admin/products`.

Verify:
- `+ New Product` opens the modal in create mode (empty, blurb visible, "Create Product" button).
- Pencil icon on a row opens the modal in edit mode (pre-filled, no blurb, "Save" button).
- Submit in create mode → redirected to `/admin/products/{slug}` (product detail).
- Submit in edit mode → redirected to `/admin/products?product_edited=<slug>`, banner shown.
- Cancel/Escape with no changes closes silently.
- Cancel/Escape with changes shows the unsaved-changes confirm.
- Slug collision (try creating with an existing slug) → red error banner on products list.

- [ ] **Step 7: Commit**

```bash
git add app/templates/products.html
git commit -m "feat(products): unified create+edit modal on products page"
```

---

## Task 5: Delete `product_new.html`

**Files:**
- Delete: `app/templates/product_new.html`

- [ ] **Step 1: Delete the template file**

Run: `Remove-Item app/templates/product_new.html`

- [ ] **Step 2: Run the full test suite**

Run: `.venv/Scripts/python.exe -m pytest tests/ -x -q`
Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add -A app/templates/product_new.html
git commit -m "chore(products): delete obsolete product_new.html template"
```

(`git add -A` here picks up the deletion since the file no longer exists.)

---

## Task 6: Version bump + full verification

**Files:**
- Modify: `app/__init__.py`

- [ ] **Step 1: Bump version**

Edit `app/__init__.py`:

```python
__version__ = "0.18.0"
```

- [ ] **Step 2: Run the full test suite**

Run: `.venv/Scripts/python.exe -m pytest tests/ -q`
Expected: All tests PASS, no warnings besides the pre-existing deprecation noise.

- [ ] **Step 3: Commit**

```bash
git add app/__init__.py
git commit -m "chore: v0.18.0 — unified product create/edit modal"
```

---

## Done. Summary of artifacts

- New service: `products.update_product`
- New route: `POST /admin/products/{slug}/edit`
- New audit event type: `product:edited` (with field-level diff)
- Deleted route: `GET /admin/products/new`
- Deleted template: `product_new.html`
- New tests: 11 in `tests/test_product_edit.py`
- Updated test: `tests/test_ui_v07.py:85`
- Version: 0.18.0
