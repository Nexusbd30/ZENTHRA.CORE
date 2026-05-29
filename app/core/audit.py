from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.db.audit_store import append_audit_record


def audit_autonomy_event(
    db: Session,
    *,
    verdict_id: str,
    actor: str,
    action: str,
    result: dict[str, Any],
    actor_role: str = "system",
    tenant_id: str = "default",
    capability: str = "",
    request_id: str = "",
) -> dict[str, Any]:
    record = append_audit_record(
        db,
        verdict_id=verdict_id,
        actor=actor,
        action=action,
        result=result,
        actor_role=actor_role,
        tenant_id=tenant_id,
        capability=capability,
        request_id=request_id,
    )
    return {
        "record_id": record.record_id,
        "hash_prev": record.hash_prev,
        "hash_self": record.hash_self,
    }
