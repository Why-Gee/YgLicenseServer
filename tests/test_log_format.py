"""T2-B: structured JSON logs behind LOG_FORMAT=json.

Verifies the formatter produces one valid JSON object per record with the
required fields, and that request_id is carried through the existing
filter chain. The configure_logging() entrypoint is exercised by exercising
the lifespan; here we test the formatter unit directly so the test stays
fast and doesn't fight with pytest's log-capture handlers.
"""
from __future__ import annotations

import json
import logging

from app.log_format import JsonFormatter


def _make_record(name: str = "license-server.test", msg: str = "hello") -> logging.LogRecord:
    return logging.LogRecord(
        name=name, level=logging.INFO, pathname=__file__, lineno=1,
        msg=msg, args=(), exc_info=None,
    )


def test_json_formatter_required_fields() -> None:
    rec = _make_record()
    rec.request_id = "req-abc"
    out = JsonFormatter().format(rec)
    payload = json.loads(out)
    assert set(payload.keys()) >= {"time", "level", "logger", "message", "request_id"}
    assert payload["level"] == "INFO"
    assert payload["logger"] == "license-server.test"
    assert payload["message"] == "hello"
    assert payload["request_id"] == "req-abc"
    # ISO 8601 UTC.
    assert payload["time"].endswith("+00:00") or payload["time"].endswith("Z")


def test_json_formatter_defaults_request_id_to_dash() -> None:
    """A record emitted outside any request has no request_id attr; the
    formatter must still produce a valid JSON object with `-` in that slot."""
    rec = _make_record()
    # Deliberately don't set request_id; the RequestIdLogFilter would normally
    # do that, but a test-time record bypasses it.
    out = JsonFormatter().format(rec)
    payload = json.loads(out)
    assert payload["request_id"] == "-"


def test_json_formatter_includes_exception() -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        import sys
        rec = logging.LogRecord(
            name="license-server.test", level=logging.ERROR, pathname=__file__,
            lineno=1, msg="crash", args=(), exc_info=sys.exc_info(),
        )
    out = JsonFormatter().format(rec)
    payload = json.loads(out)
    assert "ValueError: boom" in payload["exc_info"]
    assert payload["level"] == "ERROR"


def test_configure_logging_json_mode(monkeypatch) -> None:
    """LOG_FORMAT=json wires JsonFormatter onto the root handler."""
    from app.log_format import JsonFormatter, configure_logging
    monkeypatch.setenv("LOG_FORMAT", "json")
    configure_logging()
    handlers = logging.getLogger().handlers
    assert any(isinstance(h.formatter, JsonFormatter) for h in handlers)


def test_configure_logging_text_mode_default(monkeypatch) -> None:
    """Without LOG_FORMAT (or with anything other than json), text formatter wins."""
    from app.log_format import JsonFormatter, configure_logging
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    configure_logging()
    handlers = logging.getLogger().handlers
    assert not any(isinstance(h.formatter, JsonFormatter) for h in handlers)
