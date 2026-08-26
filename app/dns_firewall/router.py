from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.security import require_admin_or_monitor_token, require_enterprise_capability
from app.db.session import get_db
from app.dns_firewall.contracts import DnsTargetError
from app.dns_firewall.service import create_pending_rule, list_rules, preflight_target

router = APIRouter(
    prefix="/api/v1/dns-firewall",
    tags=["dns-firewall"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


class DnsPreflightRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=255)
    provider: str = Field(..., min_length=1, max_length=64)
    verdict_id: str = ""
    action: str = Field(default="block", pattern="^block$")


class DnsRuleRequest(DnsPreflightRequest):
    tenant_id: str = Field(default="default", min_length=1, max_length=120)
    change_ticket: str = Field(default="", max_length=120)
    created_by: str = Field(default="system", min_length=1, max_length=120)
    expires_at: datetime | None = None


def _rule_payload(rule) -> dict[str, object]:
    return {
        "rule_id": rule.rule_id,
        "tenant_id": rule.tenant_id,
        "target": rule.target,
        "normalized_target": rule.normalized_target,
        "target_type": rule.target_type,
        "action": rule.action,
        "provider": rule.provider,
        "status": rule.status,
        "verdict_id": rule.verdict_id,
        "change_ticket": rule.change_ticket,
        "provider_rule_id": rule.provider_rule_id,
        "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
    }


@router.post("/preflight")
def dns_preflight(
    payload: DnsPreflightRequest,
    x_tenant_id: str | None = Header(default=None),
):
    tenant_id = str(x_tenant_id or "").strip()
    if not tenant_id:
        raise HTTPException(status_code=400, detail="X-Tenant-ID is required")
    try:
        return preflight_target(
            tenant_id=tenant_id,
            target=payload.target,
            provider=payload.provider,
            verdict_id=payload.verdict_id,
            action=payload.action,
        )
    except DnsTargetError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/rules")
def register_dns_rule(
    payload: DnsRuleRequest,
    x_tenant_id: str | None = Header(default=None),
    security_context=Depends(require_enterprise_capability("security:admin")),
    db: Session = Depends(get_db),
):
    tenant_id = str(x_tenant_id or "").strip()
    if not tenant_id:
        raise HTTPException(status_code=400, detail="X-Tenant-ID is required")
    if payload.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    try:
        rule, execution = create_pending_rule(
            db,
            tenant_id=tenant_id,
            target=payload.target,
            provider=payload.provider,
            verdict_id=payload.verdict_id,
            change_ticket=payload.change_ticket,
            created_by=str(security_context.get("actor") or "system"),
            expires_at=payload.expires_at,
        )
    except DnsTargetError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "status": "pending_ares_execution",
        "rule": _rule_payload(rule),
        "execution": {
            "execution_id": execution.execution_id,
            "status": execution.status,
            "idempotency_key": execution.idempotency_key,
        },
    }


@router.get("/rules")
def read_dns_rules(
    x_tenant_id: str | None = Header(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    tenant_id = str(x_tenant_id or "").strip()
    if not tenant_id:
        raise HTTPException(status_code=400, detail="X-Tenant-ID is required")
    rows = list_rules(db, tenant_id=tenant_id, limit=limit)
    return {"count": len(rows), "items": [_rule_payload(row) for row in rows]}
