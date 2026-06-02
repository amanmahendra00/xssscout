from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from typing import Any, Protocol

from xscanner.models import Finding

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PluginContext:
    url: str
    response_text: str
    headers: dict[str, str]          # FIX: was "response_headers" in Protocol but "headers" at call-site
    content_type: str = ""            # FIX: was required, now optional with default


class AnalyzerPlugin(Protocol):
    name: str

    async def analyze(self, context: PluginContext) -> list[Finding]: ...


def load_plugins(paths: list[str]) -> list[AnalyzerPlugin]:
    plugins: list[AnalyzerPlugin] = []
    for path in paths:
        module_name, _, attr = path.partition(":")
        if not module_name or not attr:
            logger.warning("Skipping malformed plugin path %r (expected module:ClassName)", path)
            continue
        try:
            module = importlib.import_module(module_name)
            cls = getattr(module, attr)
            plugins.append(cls())
            logger.info("Loaded plugin %s", path)
        except Exception as exc:
            logger.error("Failed to load plugin %r: %s", path, exc)
    return plugins
