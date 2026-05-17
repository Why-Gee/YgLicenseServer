from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi import status as http_status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app import __version__
from app.db import SessionLocal
from app.log_format import configure_logging
from app.rate_limit import limiter, rate_limit_exceeded_handler
from app.request_id import RequestIdLogFilter, RequestIdMiddleware
from app.routers.admin_ui import ALL_ROUTERS as ADMIN_UI_ROUTERS
from app.routers.admin_ui import LoginRequired
from app.routers.api import router as api_router
from app.services.errors import ServiceError
from app.stripe_webhook import router as stripe_router


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Re-attach root handler AFTER uvicorn's dictConfig wipes it. The
    # configure_logging() helper picks text or JSON formatter based on the
    # `LOG_FORMAT` env var (default text, set `LOG_FORMAT=json` in prod for
    # structured logs that downstream ingestion can parse without a regex).
    # Uvicorn's own loggers keep their own handlers.
    configure_logging()
    # Attach the request-id filter to the root handler so every record gets
    # the `request_id` attribute set before format() runs.
    rid_filter = RequestIdLogFilter()
    for h in logging.getLogger().handlers:
        h.addFilter(rid_filter)
    _validate_secrets_at_boot()
    yield


def _validate_secrets_at_boot() -> None:
    """Fail loud if ADMIN_TOKEN / SESSION_SECRET are unset in production. The
    request-time checks return 503, but a server that boots green into
    "every admin route 503s" was easy to miss in deploy logs. Logging at
    CRITICAL means oncall sees it; setting LICENSE_SERVER_REQUIRE_SECRETS=1
    converts the warning into a hard exit for stricter deploys."""
    import os
    import sys

    from app.config import get_settings

    s = get_settings()
    log = logging.getLogger("license-server.boot")
    missing = []
    if not s.admin_token:
        missing.append("ADMIN_TOKEN")
    if not s.session_secret:
        missing.append("SESSION_SECRET")
    # Disallow reusing one secret across bearer authn + cookie signing.
    # Sharing makes them un-rotatable independently and means a leak of one
    # is a leak of both. The boot validator catches this loudly.
    if s.admin_token and s.session_secret and s.admin_token == s.session_secret:
        log.critical(
            "ADMIN_TOKEN and SESSION_SECRET are identical; they MUST be "
            "distinct so they can be rotated independently. Regenerate one."
        )
        if os.environ.get("LICENSE_SERVER_REQUIRE_SECRETS", "").lower() in ("1", "true", "yes"):
            sys.exit(78)
    # KEK is a soft-warning: signing still works without it (plaintext PEMs
    # in DB), but at-rest encryption is the desired posture in production.
    if not s.key_encryption_key:
        log.warning(
            "LICENSE_KEY_ENCRYPTION_KEY unset; product private keys are "
            "stored as plaintext PEM in the DB. Generate with "
            "`python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`"
        )
    # Production deploys that ship real customer emails must NOT use the
    # Resend public test sender (`onboarding@resend.dev`). Resend's
    # documentation is explicit that mail from that address is for
    # development only and may be rate-limited / dropped.
    if s.resend_api_key and "resend.dev" in s.email_from.lower():
        log.warning(
            "RESEND_API_KEY is set but EMAIL_FROM still points at the Resend "
            "test sender (%s); production mail will be flaky/rate-limited. "
            "Verify a domain in Resend and set EMAIL_FROM to a sender on it.",
            s.email_from,
        )
    if not missing:
        return
    msg = (
        f"missing required secrets: {', '.join(missing)}; admin UI and JSON "
        "admin API will return 503 for every request"
    )
    if os.environ.get("LICENSE_SERVER_REQUIRE_SECRETS", "").lower() in ("1", "true", "yes"):
        log.critical(msg + " (LICENSE_SERVER_REQUIRE_SECRETS=1 set; aborting)")
        sys.exit(78)  # EX_CONFIG
    log.critical(msg)


app = FastAPI(title="YgLicenseServer", version=__version__, lifespan=lifespan)
# Rate limiter: wired here so per-endpoint decorators (`@limiter.limit(...)`)
# can find `request.app.state.limiter`. See app.rate_limit for the IP-key
# logic; storage is in-process, fine for single-instance.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
# Mount the request-id middleware FIRST so it wraps every other middleware
# (incl. ones FastAPI itself adds) -- we want the id available before any
# log line the request generates, including authn/CSRF middleware lines.
app.add_middleware(RequestIdMiddleware)
app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).parent / "static"),
    name="static",
)
app.include_router(api_router)
app.include_router(stripe_router)
for _r in ADMIN_UI_ROUTERS:
    app.include_router(_r)


@app.exception_handler(LoginRequired)
async def _login_required_handler(_request: Request, _exc: LoginRequired) -> Response:
    """Unauthenticated admin-page hit → real 303 to /admin/login. Lets every
    handler just call require_login() without threading a return-redirect."""
    return RedirectResponse("/admin/login", status_code=303)


@app.exception_handler(ServiceError)
async def _service_error_handler(_request: Request, exc: ServiceError) -> Response:
    """Default mapping for unhandled service-layer exceptions: emit a JSON
    body with the stable `code` + a human-readable message at the right HTTP
    status. UI handlers that want a 303 redirect-with-?error= continue to
    catch the exception locally; this handler only fires when nothing else
    intervenes. Keeps JSON API routes free of per-call try/except boilerplate."""
    return JSONResponse(
        status_code=exc.http_status,
        content={"code": exc.code, "detail": str(exc) or exc.code},
    )


# Kubernetes-convention health endpoints. /healthz is pure liveness — proves
# the process is up and the web stack is wired. /readyz is readiness — adds a
# DB ping so callers know the server can actually issue licences. External
# monitors should probe /readyz; load balancers can use /healthz to decide
# whether to send traffic at all.
@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/readyz")
def readyz(response: Response) -> dict:
    """Liveness AND key-material readiness. Returns 200 only when:
      - the DB is reachable, AND
      - either no product has encrypted secrets, OR a sample-decrypt of one
        product's `private_key_pem` succeeds under the current KEK.

    Why sample-decrypt: a KEK mismatch (PREV not cleaned up, env wiped,
    typo on rotate) would silently 500 every issue/check; surfacing it
    here lets external monitors page before the first signed request hits
    the broken row."""
    from app.config import get_settings
    from app.keystore import decrypt_secret, is_encrypted
    from app.models import Product

    db_state = "ok"
    try:
        with SessionLocal() as s:
            s.execute(text("SELECT 1"))
    except SQLAlchemyError as e:
        db_state = type(e).__name__
    if db_state != "ok":
        response.status_code = http_status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "degraded", "version": __version__,
            "db": db_state, "kek": "unknown", "sample_decrypt": "skipped",
        }

    settings = get_settings()
    kek_state = "set" if settings.key_encryption_key else "unset"
    sample = "skipped"
    try:
        with SessionLocal() as s:
            # Find the first product with an encrypted private key (the
            # field most likely to be encrypted; products created without a
            # KEK store plaintext, which we treat as "nothing to verify").
            for p in s.query(Product).all():
                if is_encrypted(p.private_key_pem):
                    decrypt_secret(p.private_key_pem)
                    sample = "ok"
                    break
            else:
                sample = "no_encrypted_rows"
    except RuntimeError as e:
        # KEK mismatch or missing -> caller must page someone.
        sample = "fail"
        kek_state = "mismatch" if settings.key_encryption_key else "missing"
        response.status_code = http_status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "degraded", "version": __version__,
            "db": "ok", "kek": kek_state, "sample_decrypt": sample,
            "detail": str(e),
        }
    except SQLAlchemyError as e:
        response.status_code = http_status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "degraded", "version": __version__,
            "db": type(e).__name__, "kek": kek_state, "sample_decrypt": "skipped",
        }

    return {
        "status": "ok", "version": __version__,
        "db": "ok", "kek": kek_state, "sample_decrypt": sample,
    }


# Backwards-compat alias for the original /health route.
@app.get("/health")
def health() -> dict:
    return {"ok": True, "version": __version__}
