"""Shared admin-UI plumbing: templates, session cookie, CSRF, error-code map.

Imported by every admin-UI submodule under `app.routers.admin_ui`. Lives
here (not in a feature module) so adding a new feature router doesn't
require touching another one to share helpers.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeSerializer
from markupsafe import Markup

from app import __version__
from app._time import utcnow as _utcnow
from app.config import get_settings
from app.security import check_csrf, csrf_token

log = logging.getLogger("license-server.admin")

TEMPLATES_DIR = Path(__file__).parent.parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals["app_version"] = __version__

SESSION_COOKIE = "ls_session"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 7  # 7 days

PRE_MFA_COOKIE = "ls_pre_mfa"
PRE_MFA_MAX_AGE_SECONDS = 5 * 60  # 5 min window to enter the OTP

templates.env.globals["session_cookie_name"] = SESSION_COOKIE


class LoginRequired(Exception):
    """Raised by handlers when an unauthenticated visitor hits an admin page.
    `app.main` registers a handler that emits a 303 RedirectResponse — keeps
    each handler free of the redirect plumbing while emitting a real redirect
    (not a JSON HTTPException body).
    """


# Whitelist of admin-UI error codes -> human-readable messages. Templates
# render `{{ error_message(request.query_params.get('error')) }}` so a
# crafted ?error=<script> can't even show as raw text.
ERROR_MESSAGES = {
    "ai cap requires ai included": (
        'AI monthly USD cap only applies when "AI included" is ticked.'
    ),
    "email already used by another customer": "That email is already used by another customer.",
    "email required": "Email is required.",
    "invalid ai usd cap": "AI monthly USD cap must be a positive number.",
    "invalid features json": "Features JSON was not a valid object.",
    "invalid key_prefix": "Key prefix must be lowercase a–z 0–9 _, max 15 characters.",
    "invalid slug": "Slug must be lowercase a–z 0–9 –, max 63 characters.",
    "invalid valid_until": "Could not parse Valid Until date.",
    "no licenses selected": "No licenses were selected.",
    "no products selected": "No products were selected.",
    "no webhook configured": "This license has no webhook URL configured.",
    "slug exists": "A product with that slug already exists.",
    "unsafe webhook url": (
        "Webhook URL refused by SSRF guard "
        "(private/loopback/internal host or non-http(s) scheme)."
    ),
}

# Service-exception messages -> stable UI error codes (used in ?error=<code>).
SERVICE_ERR_TO_CODE: dict[str, str] = {
    "slug already exists": "slug+exists",
    "invalid slug (lowercase a-z0-9-, max 63)": "invalid+slug",
    "invalid key_prefix (lowercase a-z0-9_, max 15)": "invalid+key_prefix",
    "invalid features json": "invalid+features+json",
    "invalid ai usd cap": "invalid+ai+usd+cap",
    "ai cap requires ai included": "ai+cap+requires+ai+included",
    "invalid valid_until": "invalid+valid_until",
    "unsafe webhook url": "unsafe+webhook+url",
    "no webhook configured": "no+webhook+configured",
    "email required": "email+required",
    "email already used by another customer": "email+already+used+by+another+customer",
}


def err_code(exc: Exception) -> str:
    """Map a service exception's message to the UI's whitelisted error code.
    Falls back to a generic 'error' so the redirect never explodes."""
    return SERVICE_ERR_TO_CODE.get(str(exc), "error")


def _error_message(code: str | None) -> str | None:
    if not code:
        return None
    return ERROR_MESSAGES.get(code) or ERROR_MESSAGES.get(code.replace("+", " "))


templates.env.globals["error_message"] = _error_message


# Re-export under the legacy name `utcnow` so existing call sites in this
# package keep working without touching every import.
utcnow = _utcnow


def serializer() -> URLSafeSerializer:
    s = get_settings()
    if not s.session_secret:
        raise HTTPException(status_code=503, detail="SESSION_SECRET not set")
    return URLSafeSerializer(s.session_secret, salt="admin-session")


def pre_mfa_serializer() -> URLSafeSerializer:
    """Separate serializer salt for the pre-MFA cookie so a session-cookie
    leak cannot be replayed as a pre-MFA cookie or vice versa."""
    s = get_settings()
    if not s.session_secret:
        raise HTTPException(status_code=503, detail="SESSION_SECRET not set")
    return URLSafeSerializer(s.session_secret, salt="admin-pre-mfa")


def pre_mfa_valid(request: Request) -> bool:
    raw = request.cookies.get(PRE_MFA_COOKIE)
    if not raw:
        return False
    try:
        data = pre_mfa_serializer().loads(raw)
    except BadSignature:
        return False
    iat = data.get("iat") if isinstance(data, dict) else None
    if not isinstance(iat, int):
        return False
    return (int(time.time()) - iat) <= PRE_MFA_MAX_AGE_SECONDS


def logged_in(request: Request) -> bool:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return False
    try:
        data = serializer().loads(raw)
    except BadSignature:
        return False
    # Reject ancient cookies even if the signature still verifies. Stolen
    # cookies become useless after SESSION_MAX_AGE_SECONDS instead of
    # surviving until SESSION_SECRET rotates (which would log everyone out).
    iat = data.get("iat") if isinstance(data, dict) else None
    if not isinstance(iat, int):
        return False
    if int(time.time()) - iat > SESSION_MAX_AGE_SECONDS:
        return False
    return True


def require_login(request: Request) -> None:
    if not logged_in(request):
        raise LoginRequired()


def current_csrf_token(request: Request) -> str | None:
    """Derive the expected CSRF token for the request's session cookie. Used
    by templates to render the hidden input. Returns None when there's no
    session cookie -- the login page renders without a CSRF guard (POST to
    /admin/login is exempt; it's the bootstrap)."""
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    s = get_settings()
    if not s.session_secret:
        return None
    return csrf_token(s.session_secret, raw)


def require_csrf(request: Request, supplied: str | None) -> None:
    """Verify the CSRF token on a state-changing form POST. Raises 403 on
    mismatch."""
    raw = request.cookies.get(SESSION_COOKIE)
    s = get_settings()
    if not raw or not s.session_secret or not check_csrf(s.session_secret, raw, supplied):
        client = request.client.host if request.client else "?"
        log.warning("CSRF mismatch on %s from %s", request.url.path, client)
        raise HTTPException(status_code=403, detail="invalid CSRF token")


# `{{ csrf_input(request) }}` in any template renders the hidden input.
templates.env.globals["csrf_input"] = lambda request: Markup(
    f'<input type="hidden" name="csrf_token" value="{current_csrf_token(request) or ""}">'
)
