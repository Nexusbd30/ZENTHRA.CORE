from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PlaybookStep:
    step_id: str
    action: str
    connector: str = "soar"
    parameters: dict[str, Any] = field(default_factory=dict)
    when: dict[str, Any] = field(default_factory=dict)
    retries: int = 0
    requires_approval: bool = False
    rollback: str | None = None
    on_success: str | None = None
    on_failure: str | None = None


@dataclass(frozen=True)
class Playbook:
    playbook_id: str
    version: str
    name: str
    description: str
    triggers: list[str] = field(default_factory=list)
    steps: list[PlaybookStep] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)


def playbook_from_dict(data: dict[str, Any]) -> Playbook:
    raw_steps_value = data.get("steps")
    raw_steps = raw_steps_value if isinstance(raw_steps_value, list) else []
    raw_triggers = data.get("triggers")
    triggers = raw_triggers if isinstance(raw_triggers, list) else []
    return Playbook(
        playbook_id=str(data.get("playbook_id") or data.get("id") or ""),
        version=str(data.get("version") or "1.0.0"),
        name=str(data.get("name") or ""),
        description=str(data.get("description") or ""),
        triggers=[str(item) for item in triggers if str(item).strip()],
        labels={str(k): str(v) for k, v in dict(data.get("labels") or {}).items()},
        steps=[
            PlaybookStep(
                step_id=str(item.get("step_id") or item.get("id") or item.get("action") or ""),
                action=str(item.get("action") or ""),
                connector=str(item.get("connector") or "soar"),
                parameters=dict(item.get("parameters") or {}),
                when=dict(item.get("when") or {}),
                retries=int(item.get("retries") or 0),
                requires_approval=bool(item.get("requires_approval", False)),
                rollback=str(item.get("rollback")) if item.get("rollback") else None,
                on_success=str(item.get("on_success")) if item.get("on_success") else None,
                on_failure=str(item.get("on_failure")) if item.get("on_failure") else None,
            )
            for item in raw_steps
            if isinstance(item, dict)
        ],
    )
