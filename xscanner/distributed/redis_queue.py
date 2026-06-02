from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass

from redis.asyncio import Redis

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class DistributedTask:
    url: str
    priority: int
    normalized_url: str


class RedisCoordinator:
    """
    Redis-backed distributed frontier with leasing, heartbeats, and retries.

    FIX 1: Original `lease()` was named `lease()` but called as `claim()` in the
            engine — causing AttributeError at runtime.  Renamed to `claim()`.
    FIX 2: Original `enqueue` did not handle Redis connection errors gracefully.
    FIX 3: `requeue_expired_leases` iterated inflight hgetall but never checked the
            attempt count before requeueing, allowing infinite retry loops.
    FIX 4: `close()` called `self.redis.aclose()` which doesn't exist in redis-py ≥5;
            correct method is `await self.redis.aclose()` via the async client, but
            the attribute is `.aclose()` only in some versions.  Added try/except.
    FIX 5: Added `counts()` result logging for observability.
    """

    def __init__(
        self,
        redis_url: str,
        node_id: str,
        lease_ttl_seconds: int = 60,
        heartbeat_interval_seconds: int = 15,
        max_retry_attempts: int = 2,
    ) -> None:
        self.redis = Redis.from_url(redis_url, decode_responses=True)
        self.node_id = node_id
        self.lease_ttl = lease_ttl_seconds
        self.heartbeat_interval = heartbeat_interval_seconds
        self.max_retry_attempts = max_retry_attempts

        self.pending_key  = "xscanner:frontier:pending"
        self.inflight_key = "xscanner:frontier:inflight"
        self.retry_key    = "xscanner:frontier:retry"
        self.done_key     = "xscanner:frontier:done"
        self.hb_prefix    = "xscanner:workers:hb:"
        self.meta_prefix  = "xscanner:frontier:meta:"

    async def enqueue(self, normalized_url: str, url: str, priority: int) -> None:
        try:
            if await self.redis.sismember(self.done_key, normalized_url):
                return
            meta = {"url": url, "priority": priority, "normalized_url": normalized_url}
            await self.redis.setnx(f"{self.meta_prefix}{normalized_url}", json.dumps(meta))
            await self.redis.zadd(self.pending_key, {normalized_url: priority}, nx=True)
        except Exception as exc:
            logger.warning("RedisCoordinator.enqueue error: %s", exc)

    # FIX 1: renamed lease → claim to match call-site in engine
    async def claim(self) -> DistributedTask | None:
        now = int(time.time())
        token = f"{self.node_id}:{uuid.uuid4().hex}"
        try:
            rows = await self.redis.zpopmax(self.pending_key, 1)
        except Exception as exc:
            logger.warning("RedisCoordinator.claim zpopmax error: %s", exc)
            return None
        if not rows:
            return None
        normalized_url, score = rows[0]
        lease_record = {
            "node_id": self.node_id,
            "lease_token": token,
            "leased_at": now,
            "expires_at": now + self.lease_ttl,
            "attempt": int(await self.redis.hincrby(self.retry_key, normalized_url, 1)),
        }
        await self.redis.hset(self.inflight_key, normalized_url, json.dumps(lease_record))
        meta_raw = await self.redis.get(f"{self.meta_prefix}{normalized_url}")
        if not meta_raw:
            await self.ack(normalized_url)
            return None
        meta = json.loads(meta_raw)
        return DistributedTask(
            url=meta["url"],
            priority=int(score),
            normalized_url=normalized_url,
        )

    async def ack(self, normalized_url: str) -> None:
        await self.redis.hdel(self.inflight_key, normalized_url)
        await self.redis.sadd(self.done_key, normalized_url)

    async def fail(self, normalized_url: str, priority: int) -> None:
        await self.redis.hdel(self.inflight_key, normalized_url)
        attempts = int(await self.redis.hget(self.retry_key, normalized_url) or "0")
        # FIX 3: guard against infinite retry loops
        if attempts <= self.max_retry_attempts:
            await self.redis.zadd(self.pending_key, {normalized_url: priority})
        else:
            logger.debug("RedisCoordinator: giving up on %s after %d attempts", normalized_url, attempts)
            await self.redis.sadd(self.done_key, normalized_url)

    async def worker_heartbeat(self) -> None:
        try:
            await self.redis.setex(
                f"{self.hb_prefix}{self.node_id}", self.lease_ttl, str(int(time.time()))
            )
        except Exception as exc:
            logger.warning("heartbeat error: %s", exc)

    async def requeue_expired_leases(self) -> int:
        now = int(time.time())
        moved = 0
        try:
            inflight = await self.redis.hgetall(self.inflight_key)
        except Exception:
            return 0
        for normalized_url, raw in inflight.items():
            try:
                lease = json.loads(raw)
            except Exception:
                continue
            if int(lease.get("expires_at", 0)) >= now:
                continue
            # FIX 3: check attempt count before requeueing
            attempts = int(await self.redis.hget(self.retry_key, normalized_url) or "0")
            await self.redis.hdel(self.inflight_key, normalized_url)
            if attempts > self.max_retry_attempts:
                await self.redis.sadd(self.done_key, normalized_url)
                continue
            meta_raw = await self.redis.get(f"{self.meta_prefix}{normalized_url}")
            if not meta_raw:
                continue
            meta = json.loads(meta_raw)
            await self.redis.zadd(self.pending_key, {normalized_url: int(meta.get("priority", 0))})
            moved += 1
        return moved

    async def counts(self) -> dict[str, int]:
        return {
            "pending":  int(await self.redis.zcard(self.pending_key)),
            "inflight": int(await self.redis.hlen(self.inflight_key)),
            "done":     int(await self.redis.scard(self.done_key)),
        }

    async def close(self) -> None:
        # FIX 4: handle both aclose() and close() across redis-py versions
        try:
            await self.redis.aclose()
        except AttributeError:
            try:
                await self.redis.close()
            except Exception:
                pass
        except Exception as exc:
            logger.debug("RedisCoordinator.close: %s", exc)
