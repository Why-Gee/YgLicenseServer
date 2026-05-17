"""Service-layer exceptions. Routers map these to HTTP status codes.

Each subclass carries a `code` (machine-readable token) AND a `http_status`
default. `app.main` registers a global exception_handler that turns any
unhandled ServiceError into the corresponding HTTPException, so JSON API
handlers don't need a try/except per service call. UI handlers that want a
303-redirect-with-?error= still catch the exception locally; the default
fires only when no handler intervenes.
"""
from __future__ import annotations


class ServiceError(Exception):
    """Base for any failure surfaced from the services layer."""

    code: str = "service_error"
    http_status: int = 500


class NotFound(ServiceError):
    """Requested entity does not exist."""

    code = "not_found"
    http_status = 404


class Conflict(ServiceError):
    """State conflict: duplicate key, concurrent edit, illegal transition."""

    code = "conflict"
    http_status = 409


class ValidationFailed(ServiceError):
    """Input failed a domain rule that Pydantic alone couldn't catch
    (cross-field validation, parse of free-form JSON/date, etc.)."""

    code = "validation_failed"
    http_status = 400


class Unsafe(ServiceError):
    """Input was rejected by a safety guard (SSRF, malformed URL, etc.)."""

    code = "unsafe"
    http_status = 400
