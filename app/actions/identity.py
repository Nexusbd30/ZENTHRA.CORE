from __future__ import annotations

from app.actions._dispatch import dispatch_command
from app.actions.base import ActionResult, BaseAction
from app.core.settings import settings
from app.identity.providers import validate_identity_command

STEP_COMMANDS = {
    "resolve_identity": "identity.resolve",
    "disable_credentials": "identity.disable_credentials",
    "force_mfa": "identity.require_mfa",
    "require_mfa": "identity.require_mfa",
    "revoke_sessions": "identity.revoke_sessions",
    "degrade_privileges": "identity.degrade_privileges",
}

REVERSIBLE_STEPS = {
    "disable_credentials",
    "degrade_privileges",
}


class IdentityAction(BaseAction):
    action_type = "identity_lockdown"

    def execute_step(self, step: dict, controls: dict) -> ActionResult:
        target = step.get("payload", {}).get("target", "unknown")
        step_name = str(step.get("step") or "identity_step")
        command = STEP_COMMANDS.get(step_name, f"identity.{step_name}")
        capabilities = validate_identity_command(controls.get("identity_provider"), command)
        payload = {
            "target": target,
            "provider": capabilities.provider,
            "action_domain": controls.get("action_domain", "identity"),
            "change_ticket": controls.get("change_ticket", ""),
            "mcp_context": controls.get("mcp_context", {}),
            "provider_capabilities": {
                "supports_webhook_bridge": capabilities.supports_webhook_bridge,
                "notes": capabilities.notes,
            },
        }
        result = dispatch_command(
            url=settings.IDENTITY_CONTROL_URL,
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
            }
        return ActionResult(
            status="ok",
            detail=f"identity step executed: {step_name}",
            evidence=result,
            rollback_payload=rollback_payload,
        )

    def rollback_step(self, rollback_payload: dict) -> ActionResult:
        target = rollback_payload.get("target", "unknown")
        result = dispatch_command(
            url=settings.IDENTITY_CONTROL_URL,
            command="identity_rollback",
            payload={
                "target": target,
                "provider": rollback_payload.get("provider", "custom"),
                "from_step": rollback_payload.get("step"),
                "change_ticket": rollback_payload.get("change_ticket", ""),
            },
        )
        return ActionResult(status="ok", detail="identity rollback applied", evidence=result)
