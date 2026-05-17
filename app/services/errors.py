"""Service-layer exceptions. Routers map these to HTTP status codes."""
from __future__ import annotations


class ServiceError(Exception):
    """Base for any failure surfaced from the services layer."""

    code: str = "service_error"


class NotFound(ServiceError):
    """Requested entity does not exist."""

    code = "not_found"


class Conflict(ServiceError):
    """State conflict: duplicate key, concurrent edit, illegal transition."""

    code = "conflict"


class ValidationFailed(ServiceError):
    """Input failed a domain rule that Pydantic alone couldn't catch
    (cross-field validation, parse of free-form JSON/date, etc.)."""

    code = "validation_failed"


class Unsafe(ServiceError):
    """Input was rejected by a safety guard (SSRF, malformed URL, etc.)."""

    code = "unsafe"
