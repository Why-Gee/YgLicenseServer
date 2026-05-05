from __future__ import annotations

import logging

from fastapi import FastAPI

from app import __version__
from app.admin_ui import router as admin_ui_router
from app.api import router as api_router
from app.stripe_webhook import router as stripe_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


app = FastAPI(title="YgLicenseServer", version=__version__)
app.include_router(api_router)
app.include_router(stripe_router)
app.include_router(admin_ui_router)


@app.get("/health")
def health() -> dict:
    return {"ok": True, "version": __version__}
