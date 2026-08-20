from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

from config import settings


class JsonFormatter(logging.Formatter):
    """
    Renders every log record as one JSON object per line.

    Call sites in this project pass json.dumps({...}) as the log message
    for structured events (see api/scanner.py, api/main.py); this formatter
    merges those fields into the top-level object. Plain string messages
    are preserved under "message". Nothing in this codebase ever logs an
    Authorization header or a raw bearer token - only the short, one-way
    token fingerprint produced by security.py.
    """

    def format(self, record: logging.LogRecord) -> str:
        base = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
        }
        message = record.getMessage()
        try:
            parsed = json.loads(message)
            if isinstance(parsed, dict):
                base.update(parsed)
            else:
                base["message"] = message
        except (ValueError, TypeError):
            base["message"] = message

        if record.exc_info:
            base["exception"] = self.formatException(record.exc_info)

        return json.dumps(base)


_LEVEL_COLOR = {
    "ERROR": "\033[31m",    # red
    "WARNING": "\033[33m",  # yellow
    "INFO": "\033[36m",     # cyan
    "DEBUG": "\033[90m",    # grey
}
_RESET = "\033[0m"
_DIM = "\033[2m"

# Fields already shown positionally (timestamp/level/logger/event) - never
# repeated in the key=value tail.
_TEXT_POSITIONAL_KEYS = {"timestamp", "level", "logger", "event", "message"}


class TextFormatter(logging.Formatter):
    """
    Compact, human-readable alternative to JsonFormatter - one line per
    event (plus indented sub-lines for scan_completed's per-scanner
    detail, the thing that's actually useful when a scan errors out),
    meant for reading directly in a terminal
    (`docker compose logs -f worker`) rather than for log aggregation.
    Enabled via LOG_FORMAT=text (see config.py) - JSON stays the default
    since it's what a real log aggregator/production setup wants.

    Same parsing convention as JsonFormatter: call sites pass
    json.dumps({...}) as the log message; this formatter pulls "event"
    out for the headline and renders everything else as key=value pairs,
    with special-cased pretty-printing for the one field
    (scan_completed's scanner_results) that's actually a nested
    structure worth reading, not just a flat value.
    """

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        try:
            parsed = json.loads(message)
            if not isinstance(parsed, dict):
                parsed = {"message": message}
        except (ValueError, TypeError):
            parsed = {"message": message}

        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        level = record.levelname
        color = _LEVEL_COLOR.get(level, "")
        event = parsed.get("event") or parsed.get("message") or "-"

        scanner_results = parsed.pop("scanner_results", None)

        tail_parts = []
        for key, value in parsed.items():
            if key in _TEXT_POSITIONAL_KEYS:
                continue
            tail_parts.append(f"{key}={_short(value)}")
        tail = " ".join(tail_parts)

        line = f"{_DIM}{ts}{_RESET} {color}{level:<7}{_RESET} {_DIM}{record.name:<16}{_RESET} {event}"
        if tail:
            line += f"  {_DIM}{tail}{_RESET}"

        if scanner_results:
            for r in scanner_results:
                status_color = _LEVEL_COLOR.get("ERROR" if r.get("status") in ("ERROR", "INFECTED") else "INFO", "")
                threat = f" threat={r['threat']}" if r.get("threat") else ""
                msg = f" - {r['message']}" if r.get("message") else ""
                line += (
                    f"\n         {_DIM}->{_RESET} {r.get('scanner', '?')}: "
                    f"{status_color}{r.get('status', '?')}{_RESET}{threat}{msg}"
                )

        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)

        return line


def _short(value: object, limit: int = 200) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    text = text.replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def configure_logging() -> None:
    root = logging.getLogger()
    root.setLevel(settings.log_level.upper())
    # Avoid duplicate handlers if configure_logging() is called more than
    # once (e.g. under a test runner that imports api.main repeatedly).
    root.handlers.clear()

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if settings.log_file:
        handlers.append(logging.FileHandler(settings.log_file))

    # LOG_FORMAT=text is meant for an interactive terminal only - the
    # file handler (if LOG_FILE is set) always gets JSON regardless, so a
    # log file never ends up with ANSI color codes embedded in it.
    console_formatter = TextFormatter() if settings.log_format.lower() == "text" else JsonFormatter()
    json_formatter = JsonFormatter()
    for h in handlers:
        h.setFormatter(json_formatter if isinstance(h, logging.FileHandler) else console_formatter)
        root.addHandler(h)
