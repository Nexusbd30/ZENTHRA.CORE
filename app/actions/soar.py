from __future__ import annotations

from app.actions._dispatch import dispatch_command
from app.actions.base import ActionResult, BaseAction
from app.core.settings import settings


class SoarAction(BaseAction):
    action_type = "soar_delegate"

    def execute_step(self, step: dict, controls: dict) -> ActionResult:
        payload = {
            "target": step.get("payload", {}).get("target", "unknown"),
            "step": step.get("step", "soar_step"),
            "change_ticket": controls.get("change_ticket"),
            "threat_id": controls.get("threat_id"),
            "dry_run": bool(controls.get("dry_run", False)),
        }
        result = dispatch_command(
            url=settings.SOAR_CONTROL_URL,
            command=step.get("step", "soar_step"),
            payload=payload,
        )
        return ActionResult(
            status="ok",
            detail=f"SOAR step delegated: {step.get('step')}",
            evidence=result,
            rollback_payload={"step": step.get("step"), "target": payload["target"]},
        )

    def rollback_step(self, rollback_payload: dict) -> ActionResult:
        target = rollback_payload.get("target", "unknown")
        result = dispatch_command(
            url=settings.SOAR_CONTROL_URL,
            command="close_or_annotate_case",
            payload={
                "target": target,
                "from_step": rollback_payload.get("step"),
                "reason": "ARES transaction rollback",
            },
        )
        return ActionResult(status="ok", detail="SOAR rollback delegated", evidence=result)
