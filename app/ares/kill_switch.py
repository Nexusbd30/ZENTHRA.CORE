from __future__ import annotations

from datetime import UTC, datetime

_STATE = {
    "enabled": True,
    "reason": "",
    "actor": "system",
    "updated_at": "",
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def set_kill_switch(value: bool, *, reason: str = "", actor: str = "system") -> None:
    _STATE["enabled"] = not value
    _STATE["reason"] = reason
    _STATE["actor"] = actor
    _STATE["updated_at"] = _now()


def kill_switch_state() -> dict:
    active = not bool(_STATE["enabled"])
    return {
        "ares_enabled": bool(_STATE["enabled"]),
        "kill_switch": active,
        "active": active,
        "reason": str(_STATE["reason"]),
        "actor": str(_STATE["actor"]),
        "updated_at": str(_STATE["updated_at"]),
    }
