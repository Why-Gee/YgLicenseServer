"""Opaque-cursor keyset pagination.

Used by every admin list endpoint so a 50k-customer install doesn't ship one
giant JSON blob (or render one giant HTML table) on a single request.

Why keyset, not offset/limit:
- offset=N scans-then-discards N rows on every page request; on a large
  table that's a tax that grows linearly with the page depth.
- offset can also yield duplicate / missed rows when an insert lands between
  page N and N+1.
- A keyset cursor over `(created_at, id)` is stable under inserts and runs
  on the existing index; the cursor itself is opaque so we can change the
  encoding without breaking clients.

Encoding:
- A cursor is base64-urlsafe(`<iso-utc-naive-datetime>|<row-id>`). The pipe
  is fine because UUIDs never contain it, and the ISO datetime doesn't
  either. Base64 is just so the wire payload looks like a token rather than
  raw fields the caller might try to manipulate.

Usage (in a router):

    cursor = request.query_params.get("cursor")
    limit = clamp_limit(request.query_params.get("limit"))
    page = paginate(
        db.query(Customer).order_by(Customer.created_at.desc(), Customer.id.desc()),
        cursor_col=(Customer.created_at, Customer.id),
        cursor=cursor,
        limit=limit,
    )
    return {"items": page.items, "next_cursor": page.next_cursor}
"""
from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import and_, or_
from sqlalchemy.orm import Query
from sqlalchemy.sql.elements import ColumnElement

DEFAULT_LIMIT = 100
MAX_LIMIT = 500


def clamp_limit(raw: str | int | None, *, default: int = DEFAULT_LIMIT, max_: int = MAX_LIMIT) -> int:
    """Parse a `?limit=` query param. Falls back to `default` on missing or
    non-numeric input; caps at `max_` so a hostile caller can't ask for
    everything-in-one-page."""
    if raw is None:
        return default
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return default
    if n < 1:
        return default
    return min(n, max_)


def encode_cursor(created_at: datetime, row_id: str) -> str:
    """Pack a (created_at, id) pair into an opaque urlsafe-base64 token."""
    raw = f"{created_at.isoformat()}|{row_id}".encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_cursor(token: str | None) -> tuple[datetime, str] | None:
    """Inverse of encode_cursor. Returns None on missing or malformed input
    (caller should treat as 'start from the beginning'). Never raises -- a
    crafted cursor produces no rows, not a 500."""
    if not token:
        return None
    try:
        pad = "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(token + pad).decode("utf-8")
        ts_str, _, row_id = raw.partition("|")
        if not ts_str or not row_id:
            return None
        return datetime.fromisoformat(ts_str), row_id
    except (ValueError, TypeError):
        return None


@dataclass(frozen=True)
class Page:
    """One page of results.

    `items` is the row list (length <= limit). `next_cursor` is the token
    to feed back as `?cursor=` for the next page, or None when the caller
    has reached the end of the result set.
    """

    items: list[Any]
    next_cursor: str | None


def paginate(
    query: Query,
    *,
    cursor_col: tuple[ColumnElement[datetime], ColumnElement[str]],
    cursor: str | None,
    limit: int,
    key_fn: Callable[[Any], tuple[datetime, str]] | None = None,
) -> Page:
    """Apply a keyset cursor + limit to `query` and return a Page.

    `cursor_col` is the (created_at, id) pair the query is ordered by. The
    function appends a WHERE that selects rows STRICTLY BEFORE the cursor
    point (descending order assumed). It also fetches one extra row to
    detect "is there more?" without a separate count query.

    `key_fn` extracts `(created_at, id)` from a result row. When the query
    selects a single entity (`db.query(License)...`), the default uses
    `getattr` on the column's attribute name. When the query selects a tuple
    (`db.query(Customer, func.count(...))...`), pass `key_fn=lambda r: (r[0].created_at, r[0].id)`.
    """
    created_col, id_col = cursor_col
    decoded = decode_cursor(cursor)
    if decoded is not None:
        ts, rid = decoded
        # Keyset comparison: (created_at, id) < (cursor.created_at, cursor.id)
        # in lexicographic order. Composite-index friendly.
        query = query.filter(
            or_(
                created_col < ts,
                and_(created_col == ts, id_col < rid),
            )
        )
    rows = query.limit(limit + 1).all()
    if len(rows) > limit:
        last = rows[limit - 1]
        if key_fn is None:
            ts, rid = getattr(last, created_col.key), getattr(last, id_col.key)
        else:
            ts, rid = key_fn(last)
        return Page(items=rows[:limit], next_cursor=encode_cursor(ts, rid))
    return Page(items=rows, next_cursor=None)
