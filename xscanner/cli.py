"""
Thin shim so `xscanner` works as a console_scripts entry point.
"""
from __future__ import annotations

import asyncio
import sys


def main_sync() -> None:
    # import here to avoid circular issues at install time
    from xscanner.scanner_entry import main   # type: ignore[import]
    asyncio.run(main())


if __name__ == "__main__":
    main_sync()
