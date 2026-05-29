from __future__ import annotations

from app.actions._dispatch import dispatch_command
from app.actions.base import ActionResult, BaseAction
from app.core.settings import settings
from app.secops.providers import validate_devsecops_command

STEP_COMMANDS = {
    "resolve_pipeline": "devsecops.resolve_pipeline",
    "require_release_approval": "devsecops.require_release_approval",
    "revoke_pipeline_token": "devsecops.revoke_pipeline_token",
    "quarantine_artifact": "devsecops.quarantine_artifact",
    "block_deployment": "devsecops.block_deployment",
    "notify_release_owner": "devsecops.notify_release_owner",
}

REVERSIBLE_STEPS = {
    "require_release_approval",
    "quarantine_artifact",
    "block_deployment",
}


class DevSecOpsAction(BaseAction):
    action_type = "devsecops"

    def execute_step(self, step: dict, controls: dict) -> ActionResult:
        target = step.get("payload", {}).get("target", "unknown")
        step_name = str(step.get("step") or "devsecops_step")
        command = STEP_COMMANDS.get(step_name, f"devsecops.{step_name}")
        raw_perception = controls.get("perception")
        perception = raw_perception if isinstance(raw_perception, dict) else {}
        raw_context = perception.get("devsecops_context")
        context = (
            raw_context
            if isinstance(raw_context, dict)
            else {}
        )
        pipeline = context.get("pipeline")
        pipeline = pipeline if isinstance(pipeline, dict) else {}
        payload = {
            "target": target,
            "action_domain": controls.get("action_domain", "devsecops"),
            "provider": controls.get("devsecops_provider") or pipeline.get("provider", ""),
            "change_ticket": controls.get("change_ticket", ""),
            "mcp_context": controls.get("mcp_context", {}),
            "pipeline": pipeline,
            "actor": context.get("actor", {}),
            "finding": context.get("finding", {}),
            "controls": context.get("controls", {}),
        }
        validate_devsecops_command(payload["provider"], command)
        result = dispatch_command(
            url=settings.DEVSECOPS_CONTROL_URL,
            command=command,
            payload=payload,
        )
        rollback_payload = None
        if step_name in REVERSIBLE_STEPS:
            rollback_payload = {
                "step": step_name,
                "target": target,
                "provider": payload["provider"],
                "change_ticket": payload["change_ticket"],
                "pipeline": payload["pipeline"],
            }
        return ActionResult(
            status="ok",
            detail=f"devsecops step executed: {step_name}",
            evidence=result,
            rollback_payload=rollback_payload,
        )

    def rollback_step(self, rollback_payload: dict) -> ActionResult:
        result = dispatch_command(
            url=settings.DEVSECOPS_CONTROL_URL,
            command="devsecops.rollback",
            payload={
                "target": rollback_payload.get("target", "unknown"),
                "provider": rollback_payload.get("provider", ""),
                "from_step": rollback_payload.get("step"),
                "change_ticket": rollback_payload.get("change_ticket", ""),
                "pipeline": rollback_payload.get("pipeline", {}),
            },
        )
        return ActionResult(status="ok", detail="devsecops rollback delegated", evidence=result)
