from __future__ import annotations
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    IDLE    = "idle"
    RUNNING = "running"
    DONE    = "done"
    ERROR   = "error"


class ScanRequest(BaseModel):
    target_url:      str   = ""
    url_list_text:   str   = ""   # newline-separated URLs pasted by user
    workers:         int   = 20
    timeout:         float = 15.0
    verify_browser:  bool  = False
    verify_budget:   int   = 50
    spa_crawl:       bool  = False
    auth_header:     str   = ""
    auth_cookie:     str   = ""
    chunk_size:      int   = 500
    storage_backend: str   = "sqlite"
    resume:          bool  = False
    modules: list[str] = Field(default_factory=lambda: [
        "reflected_xss", "stored_xss", "dom_xss", "postmessage",
        "csp", "waf", "ast_taint", "browser_verify", "fp_elimination",
    ])


class ScanStats(BaseModel):
    scanned:      int   = 0
    total:        int   = 0
    confirmed:    int   = 0
    potential:    int   = 0
    dom_sinks:    int   = 0
    waf_hits:     int   = 0
    csp_issues:   int   = 0
    elapsed_s:    float = 0.0
    urls_per_min: float = 0.0


class FindingOut(BaseModel):
    id:       int
    url:      str
    param:    str | None
    type:     str
    severity: str
    evidence: dict[str, Any]


class ScanState(BaseModel):
    status:   ScanStatus = ScanStatus.IDLE
    scan_id:  str        = ""
    stats:    ScanStats  = Field(default_factory=ScanStats)
    findings: list[FindingOut] = Field(default_factory=list)
    logs:     list[dict]       = Field(default_factory=list)
    error:    str              = ""
