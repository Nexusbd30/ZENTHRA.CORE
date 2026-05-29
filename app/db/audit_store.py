from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.models.audit_record import AuditRecord
from app.models.verdict import Verdict


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
    actor_role: str = "system",
    tenant_id: str = "default",
    capability: str = "",
    request_id: str = "",
) -> AuditRecord:
    previous = db.scalar(select(AuditRecord).order_by(desc(AuditRecord.timestamp)).limit(1))
    hash_prev = previous.hash_self if previous else ""
    previous_chain_hash = previous.chain_hash if previous and previous.chain_hash else hash_prev
    max_sequence = db.scalar(select(func.max(AuditRecord.sequence_number))) or 0
    sequence_number = int(max_sequence) + 1
    timestamp = datetime.now(UTC).replace(tzinfo=None)
    result_text = _canonical(result)
    payload = {
        "verdict_id": verdict_id,
        "hash_prev": hash_prev,
        "timestamp": timestamp.isoformat(),
        "actor": actor,
        "actor_role": actor_role,
        "tenant_id": tenant_id,
        "capability": capability,
        "request_id": request_id,
        "action": action,
        "result": result,
    }
    content_hash = _hash_record(
        {
            "event_type": action,
            "actor": actor,
            "actor_role": actor_role,
            "tenant_id": tenant_id,
            "capability": capability,
            "request_id": request_id,
            "payload": result,
            "recorded_at": timestamp.isoformat(),
        }
    )
    chain_hash = hashlib.sha256(
        f"{content_hash}{previous_chain_hash}".encode("utf-8")
    ).hexdigest()
    record = AuditRecord(
        verdict_id=verdict_id,
        sequence_number=sequence_number,
        event_type=action,
        hash_prev=hash_prev,
        hash_self=_hash_record(payload),
        content_hash=content_hash,
        chain_hash=chain_hash,
        previous_chain_hash=previous_chain_hash,
        timestamp=timestamp,
        actor=actor,
        actor_role=actor_role,
        tenant_id=tenant_id,
        capability=capability,
        request_id=request_id,
        action=action,
        payload=result_text,
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


def query_audit_records(
    db: Session,
    *,
    verdict_id: str | None = None,
    event_type: str | None = None,
    actor: str | None = None,
    tenant_id: str | None = None,
    capability: str | None = None,
    from_sequence: int | None = None,
    limit: int = 50,
) -> list[AuditRecord]:
    query = select(AuditRecord).order_by(desc(AuditRecord.sequence_number)).limit(limit)
    if verdict_id:
        query = query.where(AuditRecord.verdict_id == verdict_id)
    if event_type:
        query = query.where(AuditRecord.event_type == event_type)
    if actor:
        query = query.where(AuditRecord.actor == actor)
    if tenant_id:
        query = query.where(AuditRecord.tenant_id == tenant_id)
    if capability:
        query = query.where(AuditRecord.capability == capability)
    if from_sequence is not None:
        query = query.where(AuditRecord.sequence_number >= from_sequence)
    return list(db.scalars(query).all())


def list_entity_audit_records(
    db: Session,
    *,
    entity_id: str,
    limit: int = 50,
) -> list[AuditRecord]:
    query = (
        select(AuditRecord)
        .join(Verdict, Verdict.verdict_id == AuditRecord.verdict_id)
        .where(Verdict.target == entity_id)
        .order_by(desc(AuditRecord.sequence_number))
        .limit(limit)
    )
    return list(db.scalars(query).all())


def verify_aresx_audit_chain(db: Session, *, from_sequence: int = 1) -> dict[str, Any]:
    previous = None
    if from_sequence > 1:
        previous = db.scalar(
            select(AuditRecord)
            .where(AuditRecord.sequence_number < from_sequence)
            .order_by(desc(AuditRecord.sequence_number))
            .limit(1)
        )
    records = list(
        db.scalars(
            select(AuditRecord)
            .where(AuditRecord.sequence_number >= from_sequence)
            .order_by(AuditRecord.sequence_number)
        ).all()
    )
    previous_chain_hash = previous.chain_hash if previous and previous.chain_hash else ""
    previous_sequence: int | None = previous.sequence_number if previous else None
    for record in records:
        sequence = record.sequence_number
        if sequence is None:
            return {
                "valid": False,
                "records_checked": len(records),
                "first_broken_sequence": None,
                "reason": "missing_sequence_number",
                "record_id": record.record_id,
            }
        if previous_sequence is not None and sequence != previous_sequence + 1:
            return {
                "valid": False,
                "records_checked": len(records),
                "first_broken_sequence": sequence,
                "reason": "sequence_gap",
                "record_id": record.record_id,
            }

        try:
            payload = json.loads(record.payload or record.result or "{}")
        except json.JSONDecodeError:
            payload = {"raw": record.payload or record.result}

        expected_content_hash = _hash_record(
            {
                "event_type": record.event_type or record.action,
                "actor": record.actor,
                "actor_role": record.actor_role or "system",
                "tenant_id": record.tenant_id or "default",
                "capability": record.capability or "",
                "request_id": record.request_id or "",
                "payload": payload,
                "recorded_at": record.timestamp.isoformat(),
            }
        )
        if record.content_hash and record.content_hash != expected_content_hash:
            return {
                "valid": False,
                "records_checked": len(records),
                "first_broken_sequence": sequence,
                "reason": "content_hash_mismatch",
                "record_id": record.record_id,
            }

        expected_previous = previous_chain_hash
        if record.previous_chain_hash != expected_previous:
            return {
                "valid": False,
                "records_checked": len(records),
                "first_broken_sequence": sequence,
                "reason": "previous_chain_hash_mismatch",
                "record_id": record.record_id,
            }

        expected_chain_hash = hashlib.sha256(
            f"{expected_content_hash}{expected_previous}".encode("utf-8")
        ).hexdigest()
        if record.chain_hash != expected_chain_hash:
            return {
                "valid": False,
                "records_checked": len(records),
                "first_broken_sequence": sequence,
                "reason": "chain_hash_mismatch",
                "record_id": record.record_id,
            }
        previous_chain_hash = record.chain_hash
        previous_sequence = sequence

    return {
        "valid": True,
        "records_checked": len(records),
        "first_broken_sequence": None,
    }


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
            "actor_role": record.actor_role or "system",
            "tenant_id": record.tenant_id or "default",
            "capability": record.capability or "",
            "request_id": record.request_id or "",
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
