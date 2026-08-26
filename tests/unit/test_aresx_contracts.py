from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from app.db.audit_store import append_audit_record
from app.models.audit_record import AuditRecord
from app.models.execution_result import ExecutionResult
from app.models.threat_event import ThreatEvent
from app.models.verdict import Verdict
from app.schemas.aresx_schema import (
    AresXExecutionResultCreate,
    AresXThreatEventCreate,
    AresXVerdictCreate,
)


def test_aresx_threat_event_contract_persists_canonical_fields(db_session):
    payload = AresXThreatEventCreate(
        source="qradar",
        event_id="offense-4892",
        occurred_at=datetime(2026, 2, 27, 10, 30, tzinfo=UTC),
        event_type="credential_access",
        severity=8,
        entity_id="user:alice@corp.com",
        entity_type="user",
        mitre_tags=["T1110"],
        raw_payload={"id": 4892},
        normalized_payload={"rule": "bruteforce"},
        src_ip="10.0.0.5",
        dst_ip="10.0.0.10",
        dst_port=443,
    )
    event = ThreatEvent(
        source=payload.source,
        event_id=payload.event_id,
        occurred_at=payload.occurred_at.replace(tzinfo=None) if payload.occurred_at else None,
        event_type=payload.event_type,
        severity=payload.severity,
        entity_id=payload.entity_id,
        entity_type=payload.entity_type,
        mitre_tags=json.dumps(payload.mitre_tags),
        raw_payload=json.dumps(payload.raw_payload),
        normalized_payload=json.dumps(payload.normalized_payload),
        src_ip=payload.src_ip or "",
        dst_ip=payload.dst_ip or "",
        dst_port=payload.dst_port,
    )

    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    assert event.event_id == "offense-4892"
    assert event.entity_id == "user:alice@corp.com"
    assert json.loads(event.mitre_tags) == ["T1110"]


def test_aresx_verdict_and_execution_contracts_keep_legacy_compatibility(db_session):
    verdict_payload = AresXVerdictCreate(
        threat_event_id="event-1",
        status="approved",
        severity="high",
        primary_action="force_mfa",
        confidence_score=0.82,
        risk_score=0.74,
        recommended_actions=[
            {"action_type": "force_mfa", "target": "user:alice@corp.com", "priority": 1}
        ],
        xai_explanation={"summary": "credential attack pattern"},
    )
    verdict = Verdict(
        threat_event_id=verdict_payload.threat_event_id,
        status=verdict_payload.status,
        severity=verdict_payload.severity,
        target="user:alice@corp.com",
        action_type=verdict_payload.primary_action,
        recommended_actions=json.dumps(
            [action.model_dump() for action in verdict_payload.recommended_actions]
        ),
        primary_action=verdict_payload.primary_action,
        confidence=verdict_payload.confidence_score,
        confidence_score=verdict_payload.confidence_score,
        risk_score=verdict_payload.risk_score,
        xai_explanation=json.dumps(verdict_payload.xai_explanation),
        justification_xai=verdict_payload.xai_explanation["summary"],
        policy_check=True,
    )
    db_session.add(verdict)
    db_session.commit()
    db_session.refresh(verdict)

    execution_payload = AresXExecutionResultCreate(
        verdict_id=verdict.verdict_id,
        action_type="force_mfa",
        target_entity="user:alice@corp.com",
        target_system="okta",
        status="success",
        pre_state={"mfa": "optional"},
        post_state={"mfa": "required"},
        rollback_payload={"mfa": "optional"},
        rl_reward=1.0,
    )
    execution = ExecutionResult(
        verdict_id=execution_payload.verdict_id,
        ares_id="ares",
        action_type=execution_payload.action_type,
        target_entity=execution_payload.target_entity,
        target_system=execution_payload.target_system,
        status=execution_payload.status,
        pre_state=json.dumps(execution_payload.pre_state),
        post_state=json.dumps(execution_payload.post_state),
        rollback_payload=json.dumps(execution_payload.rollback_payload),
        rl_reward=execution_payload.rl_reward,
    )
    db_session.add(execution)
    db_session.commit()
    db_session.refresh(execution)

    assert verdict.action_type == "force_mfa"
    assert verdict.confidence == verdict.confidence_score
    assert execution.target_system == "okta"
    assert json.loads(execution.rollback_payload) == {"mfa": "optional"}


def test_audit_store_populates_aresx_hash_chain_fields(db_session):
    verdict_id = f"verdict-{uuid4().hex}"
    first = append_audit_record(
        db_session,
        verdict_id=verdict_id,
        actor="redqueen",
        action="verdict_emitted",
        result={"risk_score": 0.74},
    )
    second = append_audit_record(
        db_session,
        verdict_id=verdict_id,
        actor="ares",
        action="execution_completed",
        result={"status": "success"},
        actor_role="secops_lead",
        tenant_id="tenant-contract",
        capability="ares:execute",
        request_id="req-contract",
    )

    records = (
        db_session.query(AuditRecord)
        .filter_by(verdict_id=verdict_id)
        .order_by(AuditRecord.sequence_number)
        .all()
    )

    assert [record.sequence_number for record in records] == [
        first.sequence_number,
        second.sequence_number,
    ]
    assert second.sequence_number == first.sequence_number + 1
    assert first.chain_hash
    assert second.previous_chain_hash == first.chain_hash
    assert second.event_type == "execution_completed"
    assert json.loads(second.payload) == {"status": "success"}
    assert second.actor_role == "secops_lead"
    assert second.tenant_id == "tenant-contract"
    assert second.capability == "ares:execute"
    assert second.request_id == "req-contract"
