from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.security import require_admin_or_monitor_token
from app.db.audit_store import (
    list_entity_audit_records,
    query_audit_records,
    verify_aresx_audit_chain,
)
from app.db.session import get_db
from app.models.audit_record import AuditRecord

router = APIRouter(
    prefix="/api/v1/audit",
    tags=["aresx-audit"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


class AuditVerifyRequest(BaseModel):
    from_sequence: int = Field(default=1, ge=1)


def _payload(record: AuditRecord) -> dict[str, Any]:
    try:
        value = json.loads(record.payload or record.result or "{}")
        return value if isinstance(value, dict) else {"value": value}
    except json.JSONDecodeError:
        return {"raw": record.payload or record.result}


def _record(record: AuditRecord) -> dict[str, Any]:
    return {
        "record_id": record.record_id,
        "sequence_number": record.sequence_number,
        "verdict_id": record.verdict_id,
        "event_type": record.event_type or record.action,
        "actor": record.actor,
        "actor_role": record.actor_role,
        "tenant_id": record.tenant_id,
        "capability": record.capability,
        "request_id": record.request_id,
        "payload": _payload(record),
        "content_hash": record.content_hash,
        "chain_hash": record.chain_hash,
        "previous_chain_hash": record.previous_chain_hash,
        "signature": record.signature,
        "timestamp": record.timestamp.isoformat(),
    }


@router.get("/records")
def list_records(
    verdict_id: str | None = None,
    event_type: str | None = None,
    actor: str | None = None,
    tenant_id: str | None = None,
    capability: str | None = None,
    from_sequence: int | None = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    rows = query_audit_records(
        db,
        verdict_id=verdict_id,
        event_type=event_type,
        actor=actor,
        tenant_id=tenant_id,
        capability=capability,
        from_sequence=from_sequence,
        limit=limit,
    )
    return {"count": len(rows), "items": [_record(row) for row in rows]}


@router.get("/records/{record_id}")
def read_record(record_id: str, db: Session = Depends(get_db)):
    row = db.get(AuditRecord, record_id)
    if not row:
        return {"status": "not_found", "record_id": record_id}
    return _record(row)


@router.post("/verify")
def verify_chain(payload: AuditVerifyRequest | None = None, db: Session = Depends(get_db)):
    payload = payload or AuditVerifyRequest()
    return verify_aresx_audit_chain(db, from_sequence=payload.from_sequence)


@router.get("/entity/{entity_id}")
def list_entity_records(
    entity_id: str,
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    rows = list_entity_audit_records(db, entity_id=entity_id, limit=limit)
    return {"entity_id": entity_id, "count": len(rows), "items": [_record(row) for row in rows]}
