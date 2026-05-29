from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol


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


_STORE: ReplayGuardStore = InMemoryReplayGuardStore(_SEEN)


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
