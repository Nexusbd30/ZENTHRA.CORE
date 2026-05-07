from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models.audit_record import AuditRecord


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_record(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def append_audit_record(
    db: Session,
    *,
    verdict_id: str,
    actor: str,
    action: str,
    result: dict[str, Any],
) -> AuditRecord:
    previous = db.scalar(select(AuditRecord).order_by(desc(AuditRecord.timestamp)).limit(1))
    hash_prev = previous.hash_self if previous else ""
    timestamp = datetime.now(UTC).replace(tzinfo=None)
    result_text = _canonical(result)
    payload = {
        "verdict_id": verdict_id,
        "hash_prev": hash_prev,
        "timestamp": timestamp.isoformat(),
        "actor": actor,
        "action": action,
        "result": result,
    }
    record = AuditRecord(
        verdict_id=verdict_id,
        hash_prev=hash_prev,
        hash_self=_hash_record(payload),
        timestamp=timestamp,
        actor=actor,
        action=action,
        result=result_text,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def list_audit_records(db: Session, *, verdict_id: str | None = None, limit: int = 50) -> list[AuditRecord]:
    query = select(AuditRecord).order_by(desc(AuditRecord.timestamp)).limit(limit)
    if verdict_id:
        query = (
            select(AuditRecord)
            .where(AuditRecord.verdict_id == verdict_id)
            .order_by(desc(AuditRecord.timestamp))
            .limit(limit)
        )
    return list(db.scalars(query).all())


def verify_audit_chain(db: Session) -> dict[str, Any]:
    records = list(db.scalars(select(AuditRecord).order_by(AuditRecord.timestamp)).all())
    previous_hash = ""
    for index, record in enumerate(records):
        if record.hash_prev != previous_hash:
            return {
                "valid": False,
                "count": len(records),
                "failed_at": index,
                "reason": "previous_hash_mismatch",
                "record_id": record.record_id,
            }

        try:
            result = json.loads(record.result or "{}")
        except json.JSONDecodeError:
            result = {"raw": record.result}

        payload = {
            "verdict_id": record.verdict_id,
            "hash_prev": record.hash_prev,
            "timestamp": record.timestamp.isoformat(),
            "actor": record.actor,
            "action": record.action,
            "result": result,
        }
        if _hash_record(payload) != record.hash_self:
            return {
                "valid": False,
                "count": len(records),
                "failed_at": index,
                "reason": "self_hash_mismatch",
                "record_id": record.record_id,
            }
        previous_hash = record.hash_self

    return {"valid": True, "count": len(records)}
