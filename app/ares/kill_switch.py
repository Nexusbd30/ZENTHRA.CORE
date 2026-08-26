from __future__ import annotations

import json
from collections.abc import MutableMapping
from datetime import UTC, datetime
from typing import Any, Protocol

from app.core.settings import settings

redis_module: Any | None
try:
    import redis as redis_module
except ImportError:  # pragma: no cover
    redis_module = None

redis: Any | None = redis_module


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _default_state() -> dict[str, Any]:
    return {
        "enabled": True,
        "reason": "",
        "actor": "system",
        "updated_at": "",
    }


def _public_state(
    state: MutableMapping[str, Any],
    *,
    backend: str,
    distributed: bool,
    fail_closed: bool = False,
    error: str = "",
) -> dict[str, Any]:
    enabled = bool(state.get("enabled", True)) and not fail_closed
    active = not enabled
    return {
        "ares_enabled": enabled,
        "kill_switch": active,
        "active": active,
        "reason": str(state.get("reason") or ""),
        "actor": str(state.get("actor") or "system"),
        "updated_at": str(state.get("updated_at") or ""),
        "backend": backend,
        "distributed": distributed,
        "fail_closed": fail_closed,
        "error": error,
    }


class KillSwitchStore(Protocol):
    backend_name: str
    distributed: bool

    def read(self) -> dict[str, Any]:
        ...

    def write(self, state: dict[str, Any]) -> None:
        ...

    def reset(self) -> None:
        ...


class InMemoryKillSwitchStore:
    backend_name = "in_memory"
    distributed = False

    def __init__(self, state: dict[str, Any] | None = None) -> None:
        self._state = state if state is not None else _default_state()

    def read(self) -> dict[str, Any]:
        return dict(self._state)

    def write(self, state: dict[str, Any]) -> None:
        self._state.clear()
        self._state.update(state)

    def reset(self) -> None:
        self.write(_default_state())


class RedisKillSwitchStore:
    backend_name = "redis"
    distributed = True

    def __init__(self, *, url: str, key_prefix: str, key: str) -> None:
        if redis is None:
            raise RuntimeError("redis package is required for ARES_KILL_SWITCH_BACKEND=redis")
        self._client = redis.Redis.from_url(
            url,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1,
        )
        prefix = key_prefix.strip(":") or "vaelqorix"
        normalized_key = key.strip(":") or "ares:kill_switch"
        self._key = f"{prefix}:{normalized_key}"

    @property
    def key(self) -> str:
        return self._key

    def read(self) -> dict[str, Any]:
        raw = self._client.get(self._key)
        if not raw:
            state = _default_state()
            self.write(state)
            return state
        loaded = json.loads(raw)
        if not isinstance(loaded, dict):
            raise ValueError("invalid kill-switch state payload")
        return {
            "enabled": bool(loaded.get("enabled", True)),
            "reason": str(loaded.get("reason") or ""),
            "actor": str(loaded.get("actor") or "system"),
            "updated_at": str(loaded.get("updated_at") or ""),
        }

    def write(self, state: dict[str, Any]) -> None:
        self._client.set(self._key, json.dumps(state, sort_keys=True))

    def reset(self) -> None:
        self.write(_default_state())


def _build_store() -> KillSwitchStore:
    backend = str(settings.ARES_KILL_SWITCH_BACKEND or "in_memory").strip().lower()
    if backend == "redis":
        return RedisKillSwitchStore(
            url=settings.REDIS_URL,
            key_prefix=settings.REDIS_KEY_PREFIX,
            key=settings.ARES_KILL_SWITCH_KEY,
        )
    return InMemoryKillSwitchStore()


_STORE: KillSwitchStore | None = None
_STORE_BACKEND: str | None = None


def _current_store() -> KillSwitchStore:
    global _STORE, _STORE_BACKEND
    backend = str(settings.ARES_KILL_SWITCH_BACKEND or "in_memory").strip().lower()
    if _STORE is None or _STORE_BACKEND != backend:
        _STORE = _build_store()
        _STORE_BACKEND = backend
    return _STORE


def set_kill_switch(value: bool, *, reason: str = "", actor: str = "system") -> None:
    state = {
        "enabled": not value,
        "reason": reason,
        "actor": actor,
        "updated_at": _now(),
    }
    _current_store().write(state)


def kill_switch_state() -> dict[str, Any]:
    try:
        store = _current_store()
        state = store.read()
        return _public_state(
            state,
            backend=store.backend_name,
            distributed=store.distributed,
        )
    except Exception as exc:  # noqa: BLE001
        backend = str(settings.ARES_KILL_SWITCH_BACKEND or "in_memory").strip().lower()
        return _public_state(
            {
                "enabled": False,
                "reason": "kill-switch backend unavailable",
                "actor": "system",
                "updated_at": _now(),
            },
            backend=backend,
            distributed=backend == "redis",
            fail_closed=True,
            error=str(exc),
        )


def reset_kill_switch_store() -> None:
    global _STORE, _STORE_BACKEND
    _STORE = None
    _STORE_BACKEND = None
