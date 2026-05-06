from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import __version__
from app.admin_ui import router as admin_ui_router
from app.api import router as api_router
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


@app.get("/health")
def health() -> dict:
    return {"ok": True, "version": __version__}
