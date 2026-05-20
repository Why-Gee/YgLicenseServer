# Product Create + Edit Modal — Design

**Date**: 2026-05-20
**Target version**: 0.18.0

## Goal

Let an admin both **create** and **edit** Products from a single modal on the products list page. Currently create is a dedicated page (`/admin/products/new`) and there is no edit path at all.

## Scope

**In:**
- Unified `Product` modal on `/admin/products` with two modes: create + edit.
- Mirrors the license modal pattern (single modal, mode flag, pre-filled fields, dirty-check).
- Replaces the standalone `/admin/products/new` page.

**Out:** Keypair rotation, Stripe-secret rotation, bulk edit.

## UX

**Triggers:**
- `+ New Product` button in the products card header → opens modal in **create** mode (empty fields).
- Pencil icon per row, placed before the trash icon → opens modal in **edit** mode (pre-filled from row data).

**Modal modes:**

| Mode | Title | Submit label | POST target | Post-submit redirect |
|---|---|---|---|---|
| create | "New Product" | "Create Product" | `/admin/products` | `/admin/products/{slug}` (existing behavior — lands on detail page so admin sees the freshly generated pubkey) |
| edit | "Edit Product" | "Save" | `/admin/products/{slug}/edit` | `/admin/products?product_edited={new_slug}` |

`Save` closes; Cancel/Escape/overlay-click prompts a Save/Discard/Cancel sheet when dirty. Same machinery as the license modal.

**Fields & inline notes:**

| Field | Input | Edit-mode note | Create-mode note |
|---|---|---|---|
| Slug | text, pattern `[a-z0-9][a-z0-9-]{0,62}`, required | Renaming changes admin URLs + Stripe webhook path — update any external integrations that point at the old slug. | URL-safe identifier. Lowercase, a–z 0–9 –, max 63. |
| Name | text, required | — | — |
| Key Prefix | text, pattern `[a-z0-9_]{1,15}`, required | Only affects keys issued from now on. Existing keys keep their original prefix and continue to validate. | Keys for this product will look like `<prefix>_aB7…`. Lowercase, a–z 0–9 _, max 15. |
| JWT Issuer | text, optional | Only affects JWTs issued from now on. Clients pick up the new `iss` at next phone-home. | Defaults to `<slug>-license-server`. |
| Description | textarea, optional | — | — |

**Removed:**
- `/admin/products/new` GET route — deleted.
- `app/templates/product_new.html` — deleted.

## Backend

### Service: `app/services/products.py::update_product` (new)

```python
def update_product(
    db: Session, slug: str, *,
    new_slug: str | None = None,
    name: str | None = None,
    key_prefix: str | None = None,
    jwt_issuer: str | None = None,
    description: str | None = None,
) -> Product:
    """Edit a product. Each kwarg is None = no change. Validates regex on
    new_slug + key_prefix; rejects slug collision with Conflict. Writes a
    product:edited Event with the field-level diff. Single commit."""
```

- Reuses `_SLUG_RE` and `_PREFIX_RE`.
- Builds the diff before applying changes; only changed fields go into the event payload.
- Skips the Event write entirely if nothing actually changed.

### Service: `create_product` (existing — minor change)

Set `validate_format=True` for the UI path going forward (currently `False`). The modal enforces patterns client-side, but the service should be defensive too. Caught when the form bypass-submits.

### Router: `app/routers/admin_ui/products.py`

- **Add** `product_edit`: `POST /admin/products/{slug}/edit`. Login + CSRF. On `Conflict("slug already exists")` → redirect to `/admin/products?error=slug+exists`. On `ValidationFailed` → redirect to `/admin/products?error=<code>`. Success → redirect to `/admin/products?product_edited={new_slug}`.
- **Delete** `product_new_form` route + handler (`GET /admin/products/new`).
- `product_create` (POST `/admin/products`) — keep, but on error redirect target changes from `/admin/products/new?error=...` to `/admin/products?error=...` (since the new-product page is gone). Success redirect (`/admin/products/{slug}`) unchanged.

### Audit event

```json
{
  "type": "product:edited",
  "payload": {
    "slug": "<original slug>",
    "changes": {"slug": ["old", "new"], "name": ["old", "new"], ...}
  }
}
```

Only changed fields appear in `changes`.

## Frontend

### `app/templates/products.html`

- Replace `<a class="btn" href="/admin/products/new">+ New Product</a>` with `<button type="button" class="btn" data-product-modal="create">+ New Product</button>`.
- Add edit pencil button per row (before the trash):
  ```html
  <button type="button" class="btn-icon" data-product-modal="edit" data-product-slug="{{ p.slug }}" title="Edit this product" aria-label="Edit this product">
    <svg>…pencil…</svg>
  </button>
  ```
- Add inline JSON payload `<script id="products-data">` — one entry per product with `{slug, name, key_prefix, jwt_issuer, description}`.
- Append the unified `Product Modal` markup at the end of the content block (single form with all fields).
- Inline `<script>` IIFE handling: `open(mode, product?)` populates fields, switches title/submit label/form action, dirty-check, close-on-save. Same shape as the license modal but trimmed (no webhook plumbing, no secret reveal, no email-lookup).
- Render the `?product_edited=<slug>` success banner at the top of the card.
- Render the existing `?error=<code>` banner — already handled by the template's `error_message()` block.

### `app/templates/product_new.html`

**Delete.**

### Styles

Reuse existing `.modal-overlay`, `.modal-card`, `.btn-icon`, modal-actions classes — no new CSS.

## Tests

### `tests/test_product_edit.py` (new)

**Service `update_product`:**
- Edit name + description; persisted + event payload diff matches.
- Rename slug; GET `/admin/products/<new>` 200, GET `/admin/products/<old>` 404.
- Change `key_prefix`; issue a new license; new license's key starts with new prefix; an existing license issued under old prefix still validates via `/v1/check`.
- Change `jwt_issuer`; issue a new license; minted JWT carries new `iss`.
- Slug collision with another product → `Conflict`.
- Invalid slug / key_prefix regex → `ValidationFailed`.
- No-op submit writes no Event.

**Router `POST /admin/products/{slug}/edit`:**
- POST without CSRF → 403.
- POST without login → redirect to login.
- POST against missing slug → 404.
- Successful POST → 303 to `/admin/products?product_edited=<new_slug>`.
- Slug-collision POST → 303 to `/admin/products?error=slug+exists`.

### Existing tests to update

- Any test hitting `GET /admin/products/new` → remove (the page is deleted).
- Any test that asserts the create-error redirect goes to `/admin/products/new?error=...` → update to `/admin/products?error=...`.
- `tests/test_ui_v07.py:85` asserts `href="/admin/products/new"` is present in the products page → update to assert the new modal trigger (`data-product-modal="create"`).

## Version bump

`app/__init__.py`: 0.17.0 → 0.18.0.

## Out of scope / follow-ups

- Editing Stripe secret / keypair rotation — separate flows, already on the roadmap.
- Bulk edit. YAGNI.
