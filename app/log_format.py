"""Log formatting helpers.

Two formats:
- text (default, dev-friendly): one-line `asctime LEVEL logger [req=ID]: msg`.
- json (production-friendly, set `LOG_FORMAT=json` in env): one JSON object
  per record with top-level `time`, `level`, `logger`, `message`,
  `request_id` plus exception info when present. Easy ingestion for Loki /
  Datadog / Cloud Logging without a parser stage.

Why hand-roll instead of `python-json-logger`: it adds a runtime dep we
don't otherwise need, and the format we want is exactly five fields.

The `request_id` slot is always present (RequestIdLogFilter injects it),
defaulting to `-` outside any request.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime


class JsonFormatter(logging.Formatter):
    """One JSON object per record. Keys: time (ISO-8601 UTC, millisecond
    precision), level, logger, message, request_id, plus `exc_info` when
    an exception is attached (stringified traceback)."""

    def format(self, record: logging.LogRecord) -> str:
        # Use the record's `created` timestamp (epoch float) so log
        # ingestion can correlate by `time` even if the log line is
        # buffered downstream. UTC + Z suffix for explicit timezone.
        ts = datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds")
        payload: dict[str, object] = {
            "time": ts,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack_info"] = self.formatStack(record.stack_info)
        return json.dumps(payload, ensure_ascii=False)


TEXT_FORMAT = "%(asctime)s %(levelname)s %(name)s [req=%(request_id)s]: %(message)s"


def configure_logging() -> None:
    """Wire up the root handler in the format selected by `LOG_FORMAT`.

    Called from FastAPI's lifespan with `force=True` semantics: clears
    whatever uvicorn's dictConfig left, attaches a single StreamHandler at
    INFO level with either the text or JSON formatter.
    """
    fmt = os.environ.get("LOG_FORMAT", "text").lower()
    handler = logging.StreamHandler()
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(TEXT_FORMAT))
    root = logging.getLogger()
    # Replace any existing handlers (uvicorn's dictConfig adds its own).
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
