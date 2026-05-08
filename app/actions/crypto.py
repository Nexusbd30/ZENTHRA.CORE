from __future__ import annotations

from app.actions._dispatch import dispatch_command
from app.actions.base import ActionResult, BaseAction
from app.core.settings import settings


class CryptoAction(BaseAction):
    action_type = "crypto_rotate"

    def execute_step(self, step: dict, controls: dict) -> ActionResult:
        payload = {
            "target": step.get("payload", {}).get("target", "unknown"),
            "key_id": controls.get("key_id") or controls.get("secret_ref") or "",
            "secret_ref": controls.get("secret_ref") or "",
            "change_ticket": controls.get("change_ticket"),
            "threat_id": controls.get("threat_id"),
            "reason": controls.get("reason", "ares_crypto_response"),
        }
        result = dispatch_command(
            url=settings.CRYPTO_CONTROL_URL,
            command=step.get("step", "crypto_step"),
            payload=payload,
        )
        return ActionResult(
            status="ok",
            detail=f"crypto step executed: {step.get('step')}",
            evidence=result,
            rollback_payload={
                "step": step.get("step"),
                "target": payload["target"],
                "key_id": payload["key_id"],
                "secret_ref": payload["secret_ref"],
            },
        )

    def rollback_step(self, rollback_payload: dict) -> ActionResult:
        result = dispatch_command(
            url=settings.CRYPTO_CONTROL_URL,
            command="crypto_rotation_rollback",
            payload={
                "target": rollback_payload.get("target", "unknown"),
                "key_id": rollback_payload.get("key_id", ""),
                "secret_ref": rollback_payload.get("secret_ref", ""),
                "from_step": rollback_payload.get("step"),
            },
        )
        return ActionResult(status="ok", detail="crypto rollback delegated", evidence=result)
