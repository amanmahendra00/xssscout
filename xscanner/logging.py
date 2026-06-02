from __future__ import annotations

import logging
import sys


def setup_logging(level: int = logging.INFO, json_format: bool = False) -> None:
    """
    Configure structured logging.

    FIX: Original used basicConfig only.  Added JSON format option and
         a stderr handler so log output doesn't mix with stdout JSON findings.
    """
    root = logging.getLogger()
    root.setLevel(level)

    if root.handlers:
        root.handlers.clear()

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)

    if json_format:
        import json as _json

        class _JsonFormatter(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:
                return _json.dumps({
                    "ts": self.formatTime(record),
                    "level": record.levelname,
                    "logger": record.name,
                    "msg": record.getMessage(),
                })

        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
        )

    root.addHandler(handler)

    # silence noisy third-party loggers
    for noisy in ("httpx", "httpcore", "playwright", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
