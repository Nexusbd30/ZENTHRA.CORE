from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.dns_firewall.contracts import (
    DnsTargetError,
    normalize_target,
    stable_idempotency_key,
)
from app.models.dns_firewall import DnsFirewallExecution, DnsFirewallRule


def preflight_target(
    *, tenant_id: str, target: str, provider: str, verdict_id: str = "", action: str = "block"
) -> dict[str, object]:
    normalized = normalize_target(target)
    tenant = str(tenant_id or "").strip()
    provider_name = str(provider or "").strip().lower()
    if not tenant:
        raise DnsTargetError("tenant_id is required")
    if not provider_name:
        raise DnsTargetError("DNS firewall provider is required")
    key = stable_idempotency_key(
        tenant_id=tenant,
        verdict_id=str(verdict_id or ""),
        action=str(action or "block"),
        target=normalized.value,
        step="apply_dns_firewall_block",
    )
    return {
        "allowed": True,
        "tenant_id": tenant,
        "target": normalized.value,
        "target_type": normalized.target_type,
        "provider": provider_name,
        "action": str(action or "block"),
        "idempotency_key": key,
    }


def create_pending_rule(
    db: Session,
    *,
    tenant_id: str,
    target: str,
    provider: str,
    verdict_id: str = "",
    change_ticket: str = "",
    created_by: str = "system",
    expires_at: datetime | None = None,
) -> tuple[DnsFirewallRule, DnsFirewallExecution]:
    plan = preflight_target(
        tenant_id=tenant_id,
        target=target,
        provider=provider,
        verdict_id=verdict_id,
    )
    existing = db.scalar(
        select(DnsFirewallRule).where(
            DnsFirewallRule.tenant_id == plan["tenant_id"],
            DnsFirewallRule.provider == plan["provider"],
            DnsFirewallRule.normalized_target == plan["target"],
            DnsFirewallRule.status.in_(["pending", "approved", "applied", "verified"]),
        )
    )
    if existing:
        rule = existing
    else:
        rule = DnsFirewallRule(
            tenant_id=str(plan["tenant_id"]),
            target=target.strip(),
            normalized_target=str(plan["target"]),
            target_type=str(plan["target_type"]),
            provider=str(plan["provider"]),
            verdict_id=verdict_id,
            change_ticket=change_ticket,
            created_by=created_by,
            expires_at=expires_at,
            status="pending",
        )
        db.add(rule)
        db.flush()

    key = str(plan["idempotency_key"])
    execution = db.scalar(
        select(DnsFirewallExecution).where(
            DnsFirewallExecution.tenant_id == str(plan["tenant_id"]),
            DnsFirewallExecution.idempotency_key == key,
        )
    )
    if not execution:
        execution = DnsFirewallExecution(
            tenant_id=str(plan["tenant_id"]),
            rule_id=rule.rule_id,
            verdict_id=verdict_id,
            action="block",
            status="pending",
            idempotency_key=key,
            evidence=json.dumps(plan, sort_keys=True),
        )
        db.add(execution)
    db.commit()
    db.refresh(rule)
    db.refresh(execution)
    return rule, execution


def list_rules(db: Session, *, tenant_id: str, limit: int = 50) -> list[DnsFirewallRule]:
    return list(
        db.scalars(
            select(DnsFirewallRule)
            .where(DnsFirewallRule.tenant_id == tenant_id)
            .order_by(DnsFirewallRule.created_at.desc())
            .limit(max(1, min(limit, 200)))
        ).all()
    )


def prepare_dns_execution(db: Session, *, verdict: dict, controls: dict) -> dict[str, object]:
    tenant_id = str(controls.get("tenant_id") or "default").strip()
    provider = str(
        controls.get("dns_firewall_provider")
        or controls.get("network_provider")
        or "webhook"
    ).strip()
    rule, execution = create_pending_rule(
        db,
        tenant_id=tenant_id,
        target=str(verdict.get("target") or ""),
        provider=provider,
        verdict_id=str(verdict.get("verdict_id") or ""),
        change_ticket=str(controls.get("change_ticket") or ""),
        created_by=str(controls.get("actor") or "ares"),
    )
    controls.update(
        {
            "tenant_id": tenant_id,
            "dns_firewall_provider": provider,
            "dns_firewall_rule_id": rule.rule_id,
            "dns_firewall_execution_id": execution.execution_id,
            "dns_firewall_idempotency_key": execution.idempotency_key,
        }
    )
    return {
        "rule_id": rule.rule_id,
        "execution_id": execution.execution_id,
        "idempotency_key": execution.idempotency_key,
        "status": execution.status,
    }


def update_execution_state(
    db: Session,
    *,
    execution_id: str,
    status: str,
    evidence: dict | None = None,
    provider_request_id: str = "",
    error_code: str = "",
) -> None:
    execution = db.get(DnsFirewallExecution, execution_id)
    if not execution:
        return
    execution.status = status
    if evidence is not None:
        execution.evidence = json.dumps(evidence, sort_keys=True)
    if provider_request_id:
        execution.provider_request_id = provider_request_id
    if error_code:
        execution.error_code = error_code
    db.add(execution)
    db.commit()

    rule = db.get(DnsFirewallRule, execution.rule_id)
    if rule:
        rule.status = status
        rule.last_error = error_code
        db.add(rule)
        db.commit()
