from __future__ import annotations

from app.actions._dispatch import dispatch_command
from app.actions.base import ActionResult, BaseAction
from app.core.settings import settings


class EndpointAction(BaseAction):
    action_type = "endpoint_isolate"

    def execute_step(self, step: dict, controls: dict) -> ActionResult:
        target = step.get("payload", {}).get("target", "unknown")
        result = dispatch_command(
            url=settings.ENDPOINT_CONTROL_URL,
            command=step.get("step", "endpoint_step"),
            payload={"target": target},
        )
        return ActionResult(
            status="ok",
            detail=f"endpoint step executed: {step.get('step')}",
            evidence=result,
            rollback_payload={"step": step.get("step"), "target": target},
        )

    def rollback_step(self, rollback_payload: dict) -> ActionResult:
        target = rollback_payload.get("target", "unknown")
        result = dispatch_command(
            url=settings.ENDPOINT_CONTROL_URL,
            command="endpoint_rollback",
            payload={"target": target, "from_step": rollback_payload.get("step")},
        )
        return ActionResult(status="ok", detail="endpoint rollback applied", evidence=result)
