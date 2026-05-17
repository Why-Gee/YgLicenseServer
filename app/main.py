from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi import status as http_status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app import __version__
from app.db import SessionLocal
from app.routers.admin_ui import ALL_ROUTERS as ADMIN_UI_ROUTERS
from app.routers.admin_ui import LoginRequired
from app.routers.api import router as api_router
from app.stripe_webhook import router as stripe_router


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Re-attach root handler AFTER uvicorn's dictConfig wipes it. force=True
    # clears whatever uvicorn left so app loggers ("license-server.*") emit
    # through our format. Uvicorn's own loggers keep their own handlers.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        force=True,
    )
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
    # KEK is a soft-warning: signing still works without it (plaintext PEMs
    # in DB), but at-rest encryption is the desired posture in production.
    if not s.key_encryption_key:
        log.warning(
            "LICENSE_KEY_ENCRYPTION_KEY unset; product private keys are "
            "stored as plaintext PEM in the DB. Generate with "
            "`python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`"
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
    db_state = "ok"
    try:
        with SessionLocal() as s:
            s.execute(text("SELECT 1"))
    except SQLAlchemyError as e:
        db_state = type(e).__name__
    if db_state != "ok":
        response.status_code = http_status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "degraded", "version": __version__, "db": db_state}
    return {"status": "ok", "version": __version__, "db": "ok"}


# Backwards-compat alias for the original /health route.
@app.get("/health")
def health() -> dict:
    return {"ok": True, "version": __version__}
