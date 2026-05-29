from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Protocol


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


_STORE: RateLimitStore = InMemoryRateLimitStore(_REQUESTS)


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
