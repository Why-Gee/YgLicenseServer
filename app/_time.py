"""Shared time helpers.

`utcnow()` returns a tz-NAIVE datetime representing the current UTC instant.
Naive-UTC is the storage convention used across every DateTime column on the
ORM models (see app.models._utcnow_naive); using `datetime.now(UTC).replace(tzinfo=None)`
silences the deprecation warning on `datetime.utcnow()` without changing the
wire format. Every module that needs "now" should import from here so the
convention can be enforced in one place.
"""
from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Tz-naive UTC `datetime`. Use this everywhere instead of
    `datetime.utcnow()` (deprecated) or `datetime.now(UTC).replace(...)`
    (verbose)."""
    return datetime.now(UTC).replace(tzinfo=None)
