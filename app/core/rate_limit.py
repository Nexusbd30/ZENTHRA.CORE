from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Protocol

from app.core.settings import settings

try:
    import redis
except ImportError:  # pragma: no cover - exercised by environments without redis extra
    redis = None


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int
    window_seconds: int


_REQUESTS: dict[str, deque[float]] = defaultdict(deque)


class RateLimitStore(Protocol):
    backend_name: str

    def check(self, *, key: str, limit: int, window_seconds: int) -> RateLimitDecision:
        ...

    def reset(self) -> None:
        ...


class InMemoryRateLimitStore:
    backend_name = "in_memory"

    def __init__(self, requests: dict[str, deque[float]] | None = None) -> None:
        self._requests = requests if requests is not None else defaultdict(deque)

    def check(self, *, key: str, limit: int, window_seconds: int) -> RateLimitDecision:
        normalized_limit = max(1, int(limit))
        normalized_window = max(1, int(window_seconds))
        now = time.monotonic()
        bucket = self._requests[key]
        cutoff = now - normalized_window

        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        if len(bucket) >= normalized_limit:
            retry_after = max(1, int(normalized_window - (now - bucket[0])))
            return RateLimitDecision(
                allowed=False,
                limit=normalized_limit,
                remaining=0,
                retry_after_seconds=retry_after,
                window_seconds=normalized_window,
            )

        bucket.append(now)
        return RateLimitDecision(
            allowed=True,
            limit=normalized_limit,
            remaining=max(0, normalized_limit - len(bucket)),
            retry_after_seconds=0,
            window_seconds=normalized_window,
        )

    def reset(self) -> None:
        self._requests.clear()


class RedisRateLimitStore:
    backend_name = "redis"

    def __init__(self, *, url: str, key_prefix: str) -> None:
        if redis is None:
            raise RuntimeError("redis package is required for RATE_LIMIT_BACKEND=redis")
        self._client = redis.Redis.from_url(url, decode_responses=True)
        self._key_prefix = key_prefix.strip(":") or "zenthra"

    def _key(self, key: str) -> str:
        return f"{self._key_prefix}:rate_limit:{key}"

    def check(self, *, key: str, limit: int, window_seconds: int) -> RateLimitDecision:
        normalized_limit = max(1, int(limit))
        normalized_window = max(1, int(window_seconds))
        redis_key = self._key(key)
        now_ms = int(time.time() * 1000)
        cutoff_ms = now_ms - (normalized_window * 1000)

        pipe = self._client.pipeline()
        pipe.zremrangebyscore(redis_key, 0, cutoff_ms)
        pipe.zcard(redis_key)
        _, current_count = pipe.execute()

        if int(current_count) >= normalized_limit:
            oldest = self._client.zrange(redis_key, 0, 0, withscores=True)
            retry_after = normalized_window
            if oldest:
                retry_after = max(1, int(((oldest[0][1] + normalized_window * 1000) - now_ms) / 1000))
            return RateLimitDecision(
                allowed=False,
                limit=normalized_limit,
                remaining=0,
                retry_after_seconds=retry_after,
                window_seconds=normalized_window,
            )

        member = f"{now_ms}:{time.perf_counter_ns()}"
        pipe = self._client.pipeline()
        pipe.zadd(redis_key, {member: now_ms})
        pipe.expire(redis_key, normalized_window)
        pipe.zcard(redis_key)
        _, _, new_count = pipe.execute()
        return RateLimitDecision(
            allowed=True,
            limit=normalized_limit,
            remaining=max(0, normalized_limit - int(new_count)),
            retry_after_seconds=0,
            window_seconds=normalized_window,
        )

    def reset(self) -> None:
        pattern = f"{self._key_prefix}:rate_limit:*"
        for key in self._client.scan_iter(match=pattern):
            self._client.delete(key)


def _build_store() -> RateLimitStore:
    backend = str(settings.RATE_LIMIT_BACKEND or "in_memory").strip().lower()
    if backend == "redis":
        return RedisRateLimitStore(url=settings.REDIS_URL, key_prefix=settings.REDIS_KEY_PREFIX)
    return InMemoryRateLimitStore(_REQUESTS)


_STORE: RateLimitStore = _build_store()


def rate_limit_backend_status() -> dict[str, str | bool]:
    return {
        "backend": _STORE.backend_name,
        "distributed": _STORE.backend_name != "in_memory",
        "production_recommendation": "redis_or_api_gateway",
    }


def check_rate_limit(*, key: str, limit: int, window_seconds: int) -> RateLimitDecision:
    return _STORE.check(key=key, limit=limit, window_seconds=window_seconds)


def reset_rate_limits() -> None:
    _STORE.reset()
