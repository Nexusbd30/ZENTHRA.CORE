from __future__ import annotations

from app.actions._dispatch import dispatch_command
from app.actions.base import ActionResult, BaseAction
from app.core.settings import settings
from app.dns_firewall.contracts import DnsTargetError, normalize_target
from app.dns_firewall.service import update_execution_state


class NetworkAction(BaseAction):
    action_type = "network_isolate"

    def execute_step(self, step: dict, controls: dict) -> ActionResult:
        target = step.get("payload", {}).get("target", "unknown")
        result = dispatch_command(
            url=settings.NETWORK_CONTROL_URL,
            command=step.get("step", "network_step"),
            payload={"target": target},
        )
        return ActionResult(
            status="ok",
            detail=f"network step executed: {step.get('step')}",
            evidence=result,
            rollback_payload={"step": step.get("step"), "target": target},
        )

    def rollback_step(self, rollback_payload: dict) -> ActionResult:
        target = rollback_payload.get("target", "unknown")
        result = dispatch_command(
            url=settings.NETWORK_CONTROL_URL,
            command="network_rollback",
            payload={"target": target, "from_step": rollback_payload.get("step")},
        )
        return ActionResult(status="ok", detail="network rollback applied", evidence=result)


class DnsFirewallAction(BaseAction):
    action_type = "dns_firewall_block"

    def execute_step(self, step: dict, controls: dict) -> ActionResult:
        raw_target = step.get("payload", {}).get("target", "")
        try:
            target = normalize_target(raw_target).value
        except DnsTargetError as exc:
            raise RuntimeError(str(exc)) from exc
        provider = controls.get("dns_firewall_provider") or controls.get("network_provider")
        execution_id = str(controls.get("dns_firewall_execution_id") or "")
        db = controls.get("_dns_firewall_db")
        if execution_id and db is not None and step.get("step") == "apply_dns_firewall_block":
            update_execution_state(db, execution_id=execution_id, status="dispatching")
        result = dispatch_command(
            url=settings.DNS_FIREWALL_CONTROL_URL or settings.NETWORK_CONTROL_URL,
            command=step.get("step", "dns_firewall_step"),
            payload={
                "target": target,
                "provider": provider,
                "threat_id": controls.get("threat_id"),
                "change_ticket": controls.get("change_ticket"),
                "tenant_id": controls.get("tenant_id", "default"),
                "verdict_id": controls.get("verdict_id"),
                "idempotency_key": controls.get("dns_firewall_idempotency_key"),
            },
        )
        if execution_id and db is not None:
            state = {
                "apply_dns_firewall_block": "applied",
                "verify_dns_firewall_block": "verified",
            }.get(step.get("step"), "pending")
            update_execution_state(
                db,
                execution_id=execution_id,
                status=state,
                evidence=result,
                provider_request_id=str(result.get("request_id") or result.get("id") or ""),
            )
        return ActionResult(
            status="ok",
            detail=f"dns firewall step executed: {step.get('step')}",
            evidence=result,
            rollback_payload={
                "step": step.get("step"),
                "target": target,
                "provider": provider,
                "tenant_id": controls.get("tenant_id", "default"),
                "verdict_id": controls.get("verdict_id"),
                "idempotency_key": controls.get("dns_firewall_idempotency_key"),
                "execution_id": execution_id,
                "rule_id": controls.get("dns_firewall_rule_id"),
            },
        )

    def rollback_step(self, rollback_payload: dict) -> ActionResult:
        target = rollback_payload.get("target", "unknown")
        result = dispatch_command(
            url=settings.DNS_FIREWALL_CONTROL_URL or settings.NETWORK_CONTROL_URL,
            command="dns_firewall_rollback",
            payload={
                "target": target,
                "provider": rollback_payload.get("provider"),
                "from_step": rollback_payload.get("step"),
            },
        )
        return ActionResult(status="ok", detail="dns firewall rollback applied", evidence=result)
