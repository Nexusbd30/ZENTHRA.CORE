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
) -> dict[str, Any]:
    record = append_audit_record(
        db,
        verdict_id=verdict_id,
        actor=actor,
        action=action,
        result=result,
    )
    return {
        "record_id": record.record_id,
        "hash_prev": record.hash_prev,
        "hash_self": record.hash_self,
    }
