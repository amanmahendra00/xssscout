from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class FindingType(str, Enum):
    REFLECTION             = "reflection"
    DOM_SINK               = "dom_sink"
    VERIFIED_EXECUTION     = "verified_execution"
    CSP_WEAKNESS           = "csp_weakness"
    WAF_SIGNAL             = "waf_signal"
    POSTMESSAGE_RISK       = "postmessage_risk"
    POTENTIAL_STORED_INPUT = "potential_stored_input"
    VERIFIED_REFLECTED_XSS = "verified_reflected_xss"
    HISTORICAL_ENDPOINT    = "historical_endpoint"


# FIX: Original used dataclass(slots=True) which makes __dict__ unavailable.
#      reporter.py was calling f.__dict__ on slot-based dataclasses → AttributeError.
#      We keep slots=True but reporter now uses dataclasses.asdict() correctly.

@dataclass(slots=True)
class UrlTask:
    url: str
    priority: int


@dataclass(slots=True)
class ReflectionProbe:
    param: str
    marker: str
    reflected: bool
    context: str
    encoded: bool
    escaped: bool
    executable_hint: bool


@dataclass(slots=True)
class Finding:
    url: str
    param: str | None
    type: FindingType
    severity: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RuntimeEvidence:
    alert_triggered: bool = False
    execution_proof: bool = False
    execution_token: str | None = None
    executed_payload: str | None = None
    replay_url: str | None = None
    console_events: list[str] = field(default_factory=list)
    dialog_events: list[dict[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    screenshot_path: str | None = None
    dom_snapshot_path: str | None = None
    network_events: list[str] = field(default_factory=list)
    runtime_sink_hits: list[str] = field(default_factory=list)
    dom_mutation_count: int = 0
