# Changelog

## v1.0.0 — breaking

### License-key storage

The plaintext license key is no longer stored in the admin UI listings, CSV
exports, or admin JSON API response. The server stores a BLAKE2b-keyed hash
(for /v1/check lookups) and a truncated display form (`<prefix>_<first6>…<last4>`)
for safe rendering. **Plaintext is shown exactly once at issuance** — in the
issuance HTTP response, the customer-email body, and the post-redirect admin-UI
flash banner. Save it then; you can't recover it from a DB dump.

The deprecated plaintext `key` column on the `licenses` table is retained for
this release as a safety net for in-place rollbacks. It will be dropped in v1.1.

### LICENSE_KEY_PEPPER env var

Set a 32-byte secret in `LICENSE_KEY_PEPPER`:

```
python -c 'import secrets; print(secrets.token_hex(32))'
```

This is the pepper for the at-rest hashing. **It must remain stable for the
lifetime of the deployment** — rotating it requires re-issuing every license.
Required when `LICENSE_SERVER_REQUIRE_KEK=1`; soft-warned otherwise.

### JWT aud claim

JWT payload now includes `aud = product.slug`. Client code that decodes via
`jwt.decode(token, pub, algorithms=[...], options={"verify_exp": False})` will
raise `InvalidAudienceError` until the call adds `audience=product_slug`. See
the README's client-integration example.

### Upgrade procedure

1. Generate a pepper and add `LICENSE_KEY_PEPPER=<hex>` to your env file.
2. (Optional but recommended) set `LICENSE_SERVER_REQUIRE_KEK=1` so the
   server hard-exits if either of KEK or pepper is missing.
3. Take a DB backup before upgrading. The migration backfills `key_hash` +
   `key_display` from the existing plaintext, then applies UNIQUE NOT NULL.
4. `./deploy.ps1` (or your equivalent) to ship the new image.
5. Update every client that decodes JWTs to pass `audience=product_slug`.
