from __future__ import annotations

from app.actions._dispatch import dispatch_command
from app.actions.base import ActionResult, BaseAction
from app.core.settings import settings
from app.dns_firewall.contracts import DnsBlockRequest, DnsTargetError, normalize_target
from app.dns_firewall.providers import get_provider
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

    def _request(self, *, target: str, controls: dict) -> DnsBlockRequest:
        return DnsBlockRequest(
            tenant_id=str(controls.get("tenant_id") or "default"),
            target=normalize_target(target),
            action="block",
            idempotency_key=str(controls.get("dns_firewall_idempotency_key") or ""),
            verdict_id=str(controls.get("verdict_id") or ""),
            change_ticket=str(controls.get("change_ticket") or ""),
        )

    def execute_step(self, step: dict, controls: dict) -> ActionResult:
        raw_target = step.get("payload", {}).get("target", "")
        try:
            request = self._request(target=raw_target, controls=controls)
        except DnsTargetError as exc:
            raise RuntimeError(str(exc)) from exc
        provider = controls.get("dns_firewall_provider") or controls.get("network_provider")
        execution_id = str(controls.get("dns_firewall_execution_id") or "")
        db = controls.get("_dns_firewall_db")

        if step.get("step") == "resolve_dns_indicator":
            return ActionResult(
                status="ok",
                detail="dns indicator resolved and normalized",
                evidence={
                    "target": request.target.value,
                    "target_type": request.target.target_type,
                    "tenant_id": request.tenant_id,
                    "provider": provider,
                    "idempotency_key": request.idempotency_key,
                },
            )

        dns_provider = get_provider(str(provider or "webhook"))
        if step.get("step") == "apply_dns_firewall_block":
            if execution_id and db is not None:
                update_execution_state(db, execution_id=execution_id, status="dispatched")
            provider_result = dns_provider.apply_block(request)
            if provider_result.status not in {"ok", "applied", "verified"}:
                if execution_id and db is not None:
                    update_execution_state(
                        db,
                        execution_id=execution_id,
                        status="failed",
                        evidence=provider_result.evidence or {},
                        provider_request_id=provider_result.provider_request_id,
                        provider_rule_id=provider_result.provider_rule_id,
                        error_code=provider_result.error_code or "dns_firewall_apply_failed",
                    )
                raise RuntimeError(provider_result.error_code or "DNS firewall apply failed")
            controls["dns_firewall_provider_rule_id"] = provider_result.provider_rule_id
            if execution_id and db is not None:
                update_execution_state(
                    db,
                    execution_id=execution_id,
                    status="applied",
                    evidence=provider_result.evidence or {},
                    provider_request_id=provider_result.provider_request_id,
                    provider_rule_id=provider_result.provider_rule_id,
                )
            return ActionResult(
                status="ok",
                detail="dns firewall block applied",
                evidence=provider_result.evidence or {},
                rollback_payload={
                    "step": step.get("step"),
                    "target": request.target.value,
                    "provider": provider,
                    "tenant_id": request.tenant_id,
                    "verdict_id": request.verdict_id,
                    "idempotency_key": request.idempotency_key,
                    "execution_id": execution_id,
                    "rule_id": controls.get("dns_firewall_rule_id"),
                    "provider_rule_id": provider_result.provider_rule_id,
                },
            )

        if step.get("step") == "verify_dns_firewall_block":
            provider_rule_id = str(controls.get("dns_firewall_provider_rule_id") or "")
            provider_result = dns_provider.verify_block(request, provider_rule_id)
            if provider_result.status != "verified":
                if execution_id and db is not None:
                    update_execution_state(
                        db,
                        execution_id=execution_id,
                        status="verification_failed",
                        evidence=provider_result.evidence or {},
                        provider_request_id=provider_result.provider_request_id,
                        provider_rule_id=provider_result.provider_rule_id,
                        error_code=provider_result.error_code or "dns_rule_read_back_failed",
                    )
                raise RuntimeError(provider_result.error_code or "DNS firewall verification failed")
            if execution_id and db is not None:
                update_execution_state(
                    db,
                    execution_id=execution_id,
                    status="verified",
                    evidence=provider_result.evidence or {},
                    provider_request_id=provider_result.provider_request_id,
                    provider_rule_id=provider_result.provider_rule_id,
                )
            return ActionResult(
                status="ok",
                detail="dns firewall block verified by provider read-back",
                evidence=provider_result.evidence or {},
            )

        result = dispatch_command(
            url=settings.DNS_FIREWALL_CONTROL_URL or settings.NETWORK_CONTROL_URL,
            command=step.get("step", "dns_firewall_step"),
            payload={
                "target": request.target.value,
                "provider": provider,
                "threat_id": controls.get("threat_id"),
                "change_ticket": controls.get("change_ticket"),
                "tenant_id": request.tenant_id,
                "verdict_id": request.verdict_id,
                "idempotency_key": request.idempotency_key,
            },
        )
        if execution_id and db is not None:
            update_execution_state(
                db,
                execution_id=execution_id,
                status="pending",
                evidence=result,
                provider_request_id=str(result.get("request_id") or result.get("id") or ""),
            )
        return ActionResult(
            status="ok",
            detail=f"dns firewall step executed: {step.get('step')}",
            evidence=result,
            rollback_payload={
                "step": step.get("step"),
                "target": request.target.value,
                "provider": provider,
                "tenant_id": request.tenant_id,
                "verdict_id": request.verdict_id,
                "idempotency_key": request.idempotency_key,
                "execution_id": execution_id,
                "rule_id": controls.get("dns_firewall_rule_id"),
            },
        )

    def rollback_step(self, rollback_payload: dict) -> ActionResult:
        target = rollback_payload.get("target", "unknown")
        request = DnsBlockRequest(
            tenant_id=str(rollback_payload.get("tenant_id") or "default"),
            target=normalize_target(str(target)),
            action="block",
            idempotency_key=str(rollback_payload.get("idempotency_key") or ""),
            verdict_id=str(rollback_payload.get("verdict_id") or ""),
        )
        provider = get_provider(str(rollback_payload.get("provider") or "webhook"))
        result = provider.remove_block(
            request,
            provider_rule_id=str(rollback_payload.get("provider_rule_id") or ""),
        )
        return ActionResult(
            status="ok" if result.status in {"removed", "not_found", "ok"} else "failed",
            detail="dns firewall rollback applied",
            evidence=result.evidence or {},
        )
