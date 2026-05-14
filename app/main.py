from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response, status as http_status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app import __version__
from app.admin_ui import router as admin_ui_router
from app.api import router as api_router
from app.db import SessionLocal
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
    yield


app = FastAPI(title="YgLicenseServer", version=__version__, lifespan=lifespan)
app.include_router(api_router)
app.include_router(stripe_router)
app.include_router(admin_ui_router)


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
