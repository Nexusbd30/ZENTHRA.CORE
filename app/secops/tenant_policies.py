from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.enterprise_security import normalize_tenant_id
from app.models.policy_rule import PolicyRule


def _json_loads(value: str, fallback: Any) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def policy_payload(row: PolicyRule) -> dict[str, Any]:
    return {
        "rule_id": row.rule_id,
        "tenant_id": row.tenant_id,
        "name": row.name,
        "condition_dsl": row.condition_dsl,
        "action_allowed": _json_loads(row.action_allowed, []),
        "provider_assignments": _json_loads(row.provider_assignments, {}),
        "max_autonomy_score": row.max_autonomy_score,
        "requires_human": row.requires_human,
        "enabled": row.enabled,
    }


def list_tenant_policies(db: Session, *, tenant_id: str | None = None) -> dict[str, Any]:
    query = select(PolicyRule).order_by(PolicyRule.tenant_id, PolicyRule.name, PolicyRule.rule_id)
    if tenant_id:
        query = query.where(PolicyRule.tenant_id == normalize_tenant_id(tenant_id))
    rows = list(db.scalars(query).all())
    return {
        "count": len(rows),
        "items": [policy_payload(row) for row in rows],
    }


def upsert_tenant_policy(
    db: Session,
    *,
    tenant_id: str,
    name: str,
    condition_dsl: str,
    action_allowed: list[str],
    provider_assignments: dict[str, str],
    max_autonomy_score: float,
    requires_human: bool,
    enabled: bool,
    rule_id: str | None = None,
) -> dict[str, Any]:
    normalized_tenant = normalize_tenant_id(tenant_id)
    row = db.get(PolicyRule, rule_id) if rule_id else None
    if row is None:
        row = PolicyRule()

    row.tenant_id = normalized_tenant
    row.name = name.strip() or "tenant-policy"
    row.condition_dsl = condition_dsl.strip()
    row.action_allowed = json.dumps(sorted({str(item) for item in action_allowed}), sort_keys=True)
    row.provider_assignments = json.dumps(
        {str(key): str(value) for key, value in sorted(provider_assignments.items())},
        sort_keys=True,
    )
    row.max_autonomy_score = max(0.0, min(float(max_autonomy_score), 100.0))
    row.requires_human = bool(requires_human)
    row.enabled = bool(enabled)

    db.add(row)
    db.commit()
    db.refresh(row)
    return policy_payload(row)


def tenant_policy_readiness(db: Session, *, tenant_id: str | None = None) -> dict[str, Any]:
    policies = list_tenant_policies(db, tenant_id=tenant_id)
    enabled_count = sum(1 for item in policies["items"] if item.get("enabled"))
    return {
        "persistent": True,
        "tenant_id": normalize_tenant_id(tenant_id),
        "policy_count": policies["count"],
        "enabled_policy_count": enabled_count,
        "strict_mode_ready": enabled_count > 0,
    }
