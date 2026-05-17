"""Admin UI routers, split by feature.

Each submodule exposes a `router: APIRouter` that `app.main` mounts. Shared
plumbing (templates, session auth, CSRF) lives in `_deps`.
"""
from app.routers.admin_ui import auth, customers, dashboard, events, licenses, products

# Routers in mount order. main.py imports this list and includes each.
ALL_ROUTERS = [
    auth.router,
    dashboard.router,
    products.router,
    licenses.router,
    customers.router,
    events.router,
]

# Re-export the LoginRequired exception so app.main can register its handler.
from app.routers.admin_ui._deps import LoginRequired  # noqa: E402,F401

__all__ = ["ALL_ROUTERS", "LoginRequired"]
