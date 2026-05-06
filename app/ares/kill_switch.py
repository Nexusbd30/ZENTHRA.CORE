from __future__ import annotations

_STATE = {"enabled": True}


def set_kill_switch(value: bool) -> None:
    _STATE["enabled"] = not value


def kill_switch_state() -> dict:
    return {"ares_enabled": _STATE["enabled"], "kill_switch": not _STATE["enabled"]}
