from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from pathlib import Path

logger = logging.getLogger(__name__)


async def stream_urls(path: Path, max_urls: int | None = None) -> AsyncIterator[str]:
    """
    Memory-safe URL streaming for very large URL lists.

    FIX 1: Original used a plain sync file handle inside async generator which blocks the
            event loop on each readline for large files.  We now yield control every
            `_YIELD_INTERVAL` lines so other coroutines can run during ingestion.
    FIX 2: Added basic URL validation (must start with http:// or https://).
    FIX 3: Logs a warning every 100 000 lines so operators know ingestion is alive.
    """
    _YIELD_INTERVAL = 500   # yield to event loop every N lines
    count = 0
    line_no = 0

    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line_no += 1
                if line_no % _YIELD_INTERVAL == 0:
                    await asyncio.sleep(0)           # give event loop a turn

                url = line.strip()
                if not url or url.startswith("#"):
                    continue
                if not (url.startswith("http://") or url.startswith("https://")):
                    continue                          # FIX: skip non-HTTP URLs silently

                yield url
                count += 1

                if count % 100_000 == 0:
                    logger.info("stream_urls: ingested %d URLs so far from %s", count, path)

                if max_urls is not None and count >= max_urls:
                    logger.info("stream_urls: reached max_urls limit (%d)", max_urls)
                    return

    except FileNotFoundError:
        logger.error("URL list file not found: %s", path)
        return

    logger.info("stream_urls: finished — %d URLs ingested from %s", count, path)
