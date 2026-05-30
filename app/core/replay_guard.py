from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Protocol

from app.core.settings import settings

redis_module: Any | None
try:
    import redis as redis_module
except ImportError:  # pragma: no cover
    redis_module = None

redis: Any | None = redis_module


@dataclass(frozen=True)
class ReplayDecision:
    accepted: bool
    replay_key: str
    ttl_seconds: int


_SEEN: dict[str, float] = {}


class ReplayGuardStore(Protocol):
    backend_name: str

    def check(self, *, key: str, ttl_seconds: int) -> ReplayDecision:
        ...

    def reset(self) -> None:
        ...


class InMemoryReplayGuardStore:
    backend_name = "in_memory"

    def __init__(self, seen: dict[str, float] | None = None) -> None:
        self._seen = seen if seen is not None else {}

    def check(self, *, key: str, ttl_seconds: int) -> ReplayDecision:
        normalized_ttl = max(1, int(ttl_seconds))
        now = time.monotonic()
        expired = [item for item, expires_at in self._seen.items() if expires_at <= now]
        for item in expired:
            self._seen.pop(item, None)

        if key in self._seen:
            return ReplayDecision(accepted=False, replay_key=key, ttl_seconds=normalized_ttl)

        self._seen[key] = now + normalized_ttl
        return ReplayDecision(accepted=True, replay_key=key, ttl_seconds=normalized_ttl)

    def reset(self) -> None:
        self._seen.clear()


class RedisReplayGuardStore:
    backend_name = "redis"

    def __init__(self, *, url: str, key_prefix: str) -> None:
        if redis is None:
            raise RuntimeError("redis package is required for REPLAY_GUARD_BACKEND=redis")
        self._client = redis.Redis.from_url(url, decode_responses=True)
        self._key_prefix = key_prefix.strip(":") or "zenthra"

    def _key(self, key: str) -> str:
        return f"{self._key_prefix}:replay:{key}"

    def check(self, *, key: str, ttl_seconds: int) -> ReplayDecision:
        normalized_ttl = max(1, int(ttl_seconds))
        redis_key = self._key(key)
        accepted = bool(self._client.set(redis_key, "1", nx=True, ex=normalized_ttl))
        return ReplayDecision(accepted=accepted, replay_key=key, ttl_seconds=normalized_ttl)

    def reset(self) -> None:
        pattern = f"{self._key_prefix}:replay:*"
        for key in self._client.scan_iter(match=pattern):
            self._client.delete(key)


def _build_store() -> ReplayGuardStore:
    backend = str(settings.REPLAY_GUARD_BACKEND or "in_memory").strip().lower()
    if backend == "redis":
        return RedisReplayGuardStore(url=settings.REDIS_URL, key_prefix=settings.REDIS_KEY_PREFIX)
    return InMemoryReplayGuardStore(_SEEN)


_STORE: ReplayGuardStore = _build_store()


def replay_guard_backend_status() -> dict[str, str | bool]:
    return {
        "backend": _STORE.backend_name,
        "distributed": _STORE.backend_name != "in_memory",
        "production_recommendation": "redis_or_api_gateway",
    }


def check_replay(*, key: str, ttl_seconds: int) -> ReplayDecision:
    return _STORE.check(key=key, ttl_seconds=ttl_seconds)


def reset_replay_guard() -> None:
    _STORE.reset()
