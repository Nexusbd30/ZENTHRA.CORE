from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ActionResult:
    status: str
    detail: str
    evidence: dict[str, Any] | None = None
    rollback_payload: dict[str, Any] | None = None


class BaseAction:
    action_type = "base"

    def execute_step(self, step: dict[str, Any], controls: dict[str, Any]) -> ActionResult:
        raise NotImplementedError

    def rollback_step(self, rollback_payload: dict[str, Any]) -> ActionResult:
        raise NotImplementedError
