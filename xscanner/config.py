from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class ScanConfig(BaseModel):
    """
    Central configuration for all scanner components.

    FIX 1: Added missing `evidence_dir` field (was hard-coded as "evidence" in old engine).
    FIX 2: Added validation for workers/timeout to prevent nonsensical values.
    FIX 3: Added `per_domain_rps` (requests-per-second) for WAF-aware rate limiting.
    FIX 4: `storage_backend` validator now rejects unknown backends early.
    FIX 5: `verify_budget` was unbounded — capped at 500 to prevent runaway cost.
    """

    # ── HTTP ──────────────────────────────────────────────────────
    workers: int = 20
    queue_size: int = 5000
    timeout_seconds: float = 15.0
    retries: int = 2
    user_agent: str = "xscanner/0.3"
    max_connections: int = 200
    max_keepalive_connections: int = 100
    per_domain_concurrency: int = 5
    per_domain_rps: float = 10.0          # FIX 3: requests/second per domain

    # ── Input / streaming ─────────────────────────────────────────
    max_urls: int | None = None
    chunk_size: int = 500

    # ── Browser verification ──────────────────────────────────────
    verify_browser: bool = False          # off by default — requires Playwright
    verify_budget: int = 50              # FIX 5: reasonable default, capped below
    evidence_dir: str = "evidence"       # FIX 1: was missing, hard-coded in engine

    # ── Auth ─────────────────────────────────────────────────────
    auth_header: str | None = None
    auth_cookie: str | None = None

    # ── Storage ───────────────────────────────────────────────────
    storage_backend: str = "sqlite"      # sqlite | postgres | redis

    # ── Session / resume ─────────────────────────────────────────
    resume: bool = True

    # ── Distributed ───────────────────────────────────────────────
    distributed_node_id: str = Field(default="node-local")
    distributed_enabled: bool = False
    distributed_backend: str = "redis"
    redis_url: str = "redis://localhost:6379/0"
    lease_ttl_seconds: int = 60
    heartbeat_interval_seconds: int = 15

    # ── Plugins ───────────────────────────────────────────────────
    plugin_paths: list[str] = Field(default_factory=list)

    # ── SPA crawl ─────────────────────────────────────────────────
    spa_crawl: bool = False
    spa_max_pages: int = 30
    spa_timeout_ms: int = 12000

    # ── Validators ────────────────────────────────────────────────
    @field_validator("workers")
    @classmethod
    def validate_workers(cls, v: int) -> int:
        if v < 1:
            raise ValueError("workers must be >= 1")
        if v > 500:
            raise ValueError("workers > 500 is inadvisable; use distributed mode instead")
        return v

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("timeout_seconds must be positive")
        return v

    @field_validator("verify_budget")
    @classmethod
    def validate_budget(cls, v: int) -> int:
        return min(v, 500)              # FIX 5

    @field_validator("storage_backend")
    @classmethod
    def validate_storage(cls, v: str) -> str:
        allowed = {"sqlite", "postgres", "redis"}
        if v not in allowed:
            raise ValueError(f"storage_backend must be one of {allowed}")
        return v
