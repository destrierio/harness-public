"""Structured JSON-lines logging to stderr — the only channel an entrant sees from
inside a sealed run."""
from __future__ import annotations

import json
import sys
import time


def _emit(level: str, event: str, **fields) -> None:
    rec = {"ts": round(time.time(), 3), "level": level, "event": event, **fields}
    try:
        line = json.dumps(rec, default=str)
    except (TypeError, ValueError):
        line = json.dumps({"ts": rec["ts"], "level": level, "event": event})
    print(line, file=sys.stderr, flush=True)


def info(event: str, **fields) -> None:
    _emit("info", event, **fields)


def warn(msg: str, **fields) -> None:
    _emit("warn", "warning", msg=msg, **fields)


def error(event: str, **fields) -> None:
    _emit("error", event, **fields)
