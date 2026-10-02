from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.ares.aggressive_containment import build_aggressive_containment
from app.ares.approval import build_approval_payload
from app.ares.enterprise_active_defense import build_enterprise_active_defense
from app.ares.evidence import build_ares_ai_evidence_bundle
from app.ares.hunter_trace import build_hunter_trace
from app.ares.kill_switch import kill_switch_state
from app.ares.os_business_shield import build_os_business_shield
from app.ares.response_fabric import build_response_fabric
from app.core.audit import audit_autonomy_event
from app.core.security import require_admin_or_control_token, require_enterprise_capability
from app.db.audit_store import list_audit_records, verify_audit_chain
from app.db.session import get_db
from app.models.execution_result import ExecutionResult
from app.schemas.autonomy_schema import (
    ApprovalListResponse,
    AresStatusResponse,
    AuditListResponse,
    AuditVerifyResponse,
    ExecutionResultsResponse,
    KillSwitchResponse,
    OperationFlowResponse,
)
from app.services.autonomy_service import AutonomyService

router = APIRouter(
    prefix="/api/v1/ares",
    tags=["ares"],
    dependencies=[Depends(require_admin_or_control_token)],
)


class ExecuteRequest(BaseModel):
    verdict: dict
    human_approved: bool = False
    approval_evidence: dict | None = None


class LifecycleRequest(BaseModel):
    target: str = Field(..., min_length=1)
    risk_score: float = Field(..., ge=0, le=100)
    factors: list[str] = Field(default_factory=list)
    execution_controls: dict = Field(default_factory=dict)
    human_approved: bool = False
    approval_evidence: dict | None = None


class ThreatLifecycleRequest(BaseModel):
    execution_controls: dict = Field(default_factory=dict)
    human_approved: bool = False
    approval_evidence: dict | None = None


class KillSwitchChangeRequest(BaseModel):
    reason: str = Field(..., min_length=1)
    actor: str = Field(default="admin", min_length=1)


class ApprovalRequest(BaseModel):
    verdict: dict
    approver: str = Field(..., min_length=1)
    reason: str = ""


class RollbackRequest(BaseModel):
    reason: str = Field(..., min_length=1)
    actor: str = Field(default="admin", min_length=1)


class ShieldPlanRequest(BaseModel):
    target: str = Field(..., min_length=1)
    action_type: str = Field(default="system_harden", min_length=1)
    anticipation: dict = Field(default_factory=dict)
    execution_controls: dict = Field(default_factory=dict)


class ContainmentPlanRequest(BaseModel):
    verdict: dict = Field(default_factory=dict)
    bridge_trace: dict = Field(default_factory=dict)
    execution_controls: dict = Field(default_factory=dict)


class EnterpriseActiveDefenseRequest(BaseModel):
    verdict: dict = Field(default_factory=dict)
    bridge_trace: dict = Field(default_factory=dict)
    execution_controls: dict = Field(default_factory=dict)


class ResponseFabricRequest(BaseModel):
    verdict: dict = Field(default_factory=dict)
    strategic_anticipation: dict = Field(default_factory=dict)
    enterprise_active_defense: dict = Field(default_factory=dict)
    execution_controls: dict = Field(default_factory=dict)


class HunterTraceRequest(BaseModel):
    target: str = Field(..., min_length=1)
    verdict_id: str | None = None
    limit: int = Field(default=100, ge=1, le=500)
    execution_controls: dict = Field(default_factory=dict)


def _json_loads(value: str | None, fallback):
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def _execution_payload(row: ExecutionResult) -> dict:
    return {
        "id": row.id,
        "verdict_id": row.verdict_id,
        "ares_id": row.ares_id,
        "action_type": row.action_type,
        "target_entity": row.target_entity,
        "target_system": row.target_system,
        "status": row.status,
        "duration_ms": row.duration_ms,
        "pre_state": _json_loads(row.pre_state, {}),
        "post_state": _json_loads(row.post_state, {}),
        "evidence": _json_loads(row.evidence, []),
        "rollback_payload": _json_loads(row.rollback_payload, {}),
        "rl_reward": row.rl_reward,
        "error_code": row.error_code,
        "result_hash": row.result_hash,
        "timestamp": row.timestamp.isoformat(),
    }


@router.get("/status", response_model=AresStatusResponse)
def ares_status():
    return {
        "module": "ares",
        "role": "executor_of_redqueen_orders",
        "phase": "phase-2-core",
        "internal_firewall": {
            "schema": "vaelqorix.ares.internal_firewall.v1",
            "status": "enabled",
            "blocks": [
                "mcp_action_denied",
                "mcp_tool_denied",
                "firewall_action_denied",
                "firewall_action_not_allowed",
                "protected_target_without_owner_approval",
                "advisor_marked_unsafe_when_enforced",
            ],
        },
        "os_business_shield": {
            "schema": "vaelqorix.ares.os_business_shield.v1",
            "status": "enabled",
            "purpose": "preventive_defense_for_operating_system_and_business_services",
        },
        "aggressive_containment": {
            "schema": "vaelqorix.ares.aggressive_containment.v1",
            "status": "enabled",
            "purpose": "authorized_active_defense_to_neutralize_observed_intrusions",
        },
        "enterprise_active_defense": {
            "schema": "vaelqorix.ares.enterprise_active_defense.v1",
            "status": "enabled",
            "purpose": "enterprise_grade_blocking_deception_sinkhole_and_legal_evidence",
        },
        "response_fabric": {
            "schema": "vaelqorix.ares.response_fabric.v1",
            "status": "enabled",
            "purpose": "route_next_best_actions_across_ready_enterprise_connectors",
        },
        "hunter_trace": {
            "schema": "vaelqorix.ares.hunter_trace.v1",
            "status": "enabled",
            "purpose": "trace_intruder_presence_inside_owned_environment_and_prepare_eviction",
            "safety_boundary": "owned_or_authorized_assets_only",
        },
        "kill_switch": kill_switch_state(),
    }


@router.get("/kill-switch", response_model=KillSwitchResponse)
def get_kill_switch():
    return {"status": "ok", "kill_switch": kill_switch_state()}


@router.post("/kill-switch/activate", response_model=KillSwitchResponse)
def activate_kill_switch(payload: KillSwitchChangeRequest, db: Session = Depends(get_db)):
    from app.ares.kill_switch import set_kill_switch

    set_kill_switch(True, reason=payload.reason, actor=payload.actor)
    audit_autonomy_event(
        db,
        verdict_id="kill-switch",
        actor=payload.actor,
        action="kill_switch_activated",
        result={"reason": payload.reason, "state": kill_switch_state()},
    )
    return {"status": "ok", "kill_switch": kill_switch_state()}


@router.post("/kill-switch/deactivate", response_model=KillSwitchResponse)
def deactivate_kill_switch(payload: KillSwitchChangeRequest, db: Session = Depends(get_db)):
    from app.ares.kill_switch import set_kill_switch

    set_kill_switch(False, reason=payload.reason, actor=payload.actor)
    audit_autonomy_event(
        db,
        verdict_id="kill-switch",
        actor=payload.actor,
        action="kill_switch_deactivated",
        result={"reason": payload.reason, "state": kill_switch_state()},
    )
    return {"status": "ok", "kill_switch": kill_switch_state()}


@router.post("/kill-switch/{mode}", response_model=KillSwitchResponse)
def set_kill_switch(mode: str):
    mode = mode.lower().strip()
    if mode not in {"on", "off"}:
        return {"status": "error", "detail": "mode must be on/off"}
    from app.ares.kill_switch import set_kill_switch

    set_kill_switch(mode == "on")
    return {"status": "ok", "kill_switch": kill_switch_state()}


@router.get("/operation-flow", response_model=OperationFlowResponse)
def get_operation_flow():
    return {
        "name": "alert_to_evidence",
        "stages": [
            {
                "key": "alert_received",
                "label": "Alertmanager webhook received",
                "endpoint": "/hooks/alertmanager",
                "owner": "monitoring",
                "ui_surface": "Evidence timeline",
                "produces": ["response_log.id", "payload_hash", "alert_count"],
            },
            {
                "key": "threat_created",
                "label": "SIEM event correlated into threat",
                "endpoint": "/threats/",
                "owner": "correlation_engine",
                "ui_surface": "Threat detail",
                "produces": ["threat.id", "fingerprint", "siem_metadata"],
            },
            {
                "key": "redqueen_verdict",
                "label": "RedQueen intrusion-control verdict",
                "endpoint": "/api/v1/redqueen/verdict/from-threat/{threat_id}",
                "owner": "redqueen",
                "ui_surface": "RedQueen Brain",
                "produces": ["verdict_id", "risk_score", "action_type", "justification_xai"],
            },
            {
                "key": "ares_plan",
                "label": "ARES validation and execution of RedQueen order",
                "endpoint": "/api/v1/ares/lifecycle/from-threat/{threat_id}",
                "owner": "ares",
                "ui_surface": "ARES Shield",
                "produces": ["plan", "advisor_review", "execution_controls"],
                "requires_human": True,
            },
            {
                "key": "evidence",
                "label": "Execution results and audit chain",
                "endpoint": "/api/v1/ares/results/{verdict_id}",
                "owner": "ares",
                "ui_surface": "Evidence timeline",
                "produces": ["result_hash", "duration_ms", "audit_records"],
            },
        ],
        "evidence_sources": [
            "/monitoring/response-logs",
            "/api/v1/ares/results/{verdict_id}",
            "/api/v1/ares/audit",
            "/api/v1/ares/audit/verify",
        ],
        "frontend_entrypoints": {
            "command_center": "/monitoring/production-readiness",
            "redqueen": "/api/v1/redqueen/verdict/from-threat/{threat_id}",
            "ares": "/api/v1/ares/lifecycle/from-threat/{threat_id}",
            "evidence": "/api/v1/ares/results/{verdict_id}",
        },
        "notes": [
            "Use dry_run for operator previews.",
            "RedQueen decides independently; ARES is the only execution path for operational actions.",
            "Disruptive actions require traceability and may require signed human approval.",
        ],
    }


@router.post("/shield/plan")
def build_shield_plan(payload: ShieldPlanRequest):
    return build_os_business_shield(
        target=payload.target,
        action_type=payload.action_type,
        anticipation=payload.anticipation,
        controls=payload.execution_controls,
    )


@router.post("/containment/plan")
def build_containment_plan(payload: ContainmentPlanRequest):
    return build_aggressive_containment(
        verdict=payload.verdict,
        bridge_trace=payload.bridge_trace,
        controls=payload.execution_controls,
    )


@router.post("/active-defense/plan")
def build_active_defense_plan(payload: EnterpriseActiveDefenseRequest):
    return build_enterprise_active_defense(
        verdict=payload.verdict,
        bridge_trace=payload.bridge_trace,
        controls=payload.execution_controls,
    )


@router.post("/response-fabric/plan")
def build_response_fabric_plan(payload: ResponseFabricRequest):
    return build_response_fabric(
        verdict=payload.verdict,
        strategic_anticipation=payload.strategic_anticipation,
        enterprise_active_defense=payload.enterprise_active_defense,
        controls=payload.execution_controls,
    )


@router.get("/hunter-trace")
def get_hunter_trace(
    target: str,
    verdict_id: str | None = None,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    return build_hunter_trace(db, target=target, verdict_id=verdict_id, limit=limit)


@router.post("/hunter-trace")
def post_hunter_trace(payload: HunterTraceRequest, db: Session = Depends(get_db)):
    return build_hunter_trace(
        db,
        target=payload.target,
        verdict_id=payload.verdict_id,
        limit=payload.limit,
        controls=payload.execution_controls,
    )


@router.get("/hunter-trace/from-verdict/{verdict_id}")
def get_hunter_trace_from_verdict(
    verdict_id: str,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    stored_verdict = AutonomyService.get_verdict(db, verdict_id)
    if not stored_verdict:
        return {"status": "not_found", "verdict_id": verdict_id}
    return build_hunter_trace(
        db,
        target=stored_verdict.target,
        verdict_id=verdict_id,
        limit=limit,
    )


@router.post("/execute")
def execute_verdict(payload: ExecuteRequest, db: Session = Depends(get_db)):
    return AutonomyService.execute_verdict(
        db,
        verdict=payload.verdict,
        human_approved=payload.human_approved,
        approval_evidence=payload.approval_evidence,
    )


@router.post("/approval-token")
def create_approval_token(
    payload: ApprovalRequest,
    auth_context=Depends(require_enterprise_capability("ares:approve")),
):
    if auth_context.get("role") == "service":
        raise HTTPException(status_code=403, detail="Human approval requires an authenticated user")
    actor = auth_context["actor"]
    return build_approval_payload(
        verdict=payload.verdict,
        approver=actor,
        reason=payload.reason,
    )


@router.post("/lifecycle")
def run_lifecycle(payload: LifecycleRequest, db: Session = Depends(get_db)):
    verdict = AutonomyService.issue_verdict(
        db,
        target=payload.target,
        risk_score=payload.risk_score,
        factors=payload.factors,
        execution_controls=payload.execution_controls,
    )
    execution_response = AutonomyService.execute_verdict(
        db,
        verdict=verdict,
        human_approved=payload.human_approved,
        approval_evidence=payload.approval_evidence,
    )

    return {
        "verdict": verdict,
        "execution": execution_response,
    }


@router.post("/lifecycle/from-threat/{threat_id}")
def run_lifecycle_from_threat(
    threat_id: str,
    payload: ThreatLifecycleRequest | None = None,
    db: Session = Depends(get_db),
):
    payload = payload or ThreatLifecycleRequest()
    verdict_response = AutonomyService.issue_verdict_from_threat(
        db,
        threat_id=threat_id,
        execution_controls=payload.execution_controls,
    )
    if verdict_response.get("status") == "not_found":
        return verdict_response

    verdict = verdict_response["verdict"]
    execution_response = AutonomyService.execute_verdict(
        db,
        verdict=verdict,
        human_approved=payload.human_approved,
        approval_evidence=payload.approval_evidence,
    )

    return {
        **verdict_response,
        "execution": execution_response,
    }


@router.post("/lifecycle/from-event/{event_id}")
def run_lifecycle_from_event(
    event_id: str,
    payload: ThreatLifecycleRequest | None = None,
    db: Session = Depends(get_db),
):
    payload = payload or ThreatLifecycleRequest()
    verdict_response = AutonomyService.issue_verdict_from_threat_event(
        db,
        event_id=event_id,
        execution_controls=payload.execution_controls,
    )
    if verdict_response.get("status") == "not_found":
        return verdict_response

    verdict = verdict_response["verdict"]
    execution_response = AutonomyService.execute_verdict(
        db,
        verdict=verdict,
        human_approved=payload.human_approved,
        approval_evidence=payload.approval_evidence,
    )

    return {
        **verdict_response,
        "execution": execution_response,
    }


@router.get("/executions")
def list_executions(
    verdict_id: str | None = None,
    status: str | None = None,
    target_entity: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    query = (
        select(ExecutionResult)
        .order_by(desc(ExecutionResult.timestamp))
        .limit(max(1, min(limit, 200)))
    )
    if verdict_id:
        query = query.where(ExecutionResult.verdict_id == verdict_id)
    if status:
        query = query.where(ExecutionResult.status == status)
    if target_entity:
        query = query.where(ExecutionResult.target_entity == target_entity)
    rows = list(db.scalars(query).all())
    return {
        "count": len(rows),
        "items": [_execution_payload(row) for row in rows],
    }


@router.get("/executions/{execution_id}")
def read_execution(execution_id: str, db: Session = Depends(get_db)):
    row = db.get(ExecutionResult, execution_id)
    if not row:
        return {"status": "not_found", "execution_id": execution_id}
    return _execution_payload(row)


@router.post("/executions/{execution_id}/rollback")
def rollback_execution(
    execution_id: str,
    payload: RollbackRequest,
    db: Session = Depends(get_db),
):
    row = db.get(ExecutionResult, execution_id)
    if not row:
        return {"status": "not_found", "execution_id": execution_id}
    from app.ares.executor import ACTION_EXECUTORS, ActionTransaction
    from app.dns_firewall.service import update_execution_state

    if row.status == "rolled_back":
        return _execution_payload(row)
    executor = ACTION_EXECUTORS.get(row.action_type)
    saved = _json_loads(row.rollback_payload, {})
    steps = saved.get("steps", [])
    if executor is None or not steps:
        raise HTTPException(status_code=409, detail="No executable rollback evidence is available")
    tx = ActionTransaction(executor)
    for step in steps:
        tx.record(step)
    events = tx.rollback()
    succeeded = bool(events) and all(event["status"] == "ok" for event in events)
    row.status = "rolled_back" if succeeded else "rollback_failed"
    row.rollback_payload = json.dumps({**saved, "rollback_events": events, "reason": payload.reason}, sort_keys=True)
    db.add(row)
    db.commit()
    for step in steps:
        if row.action_type == "dns_firewall_block" and step.get("execution_id"):
            update_execution_state(db, execution_id=step["execution_id"], status=row.status,
                                   evidence={"rollback_events": events})
    audit_autonomy_event(db, verdict_id=row.verdict_id, actor="ares", action="execution_rollback",
                         result={"execution_id": row.id, "status": row.status, "reason": payload.reason,
                                 "original_result_hash": row.result_hash, "rollback_events": events})
    db.refresh(row)
    return _execution_payload(row)


@router.get("/results/{verdict_id}", response_model=ExecutionResultsResponse)
def list_results(verdict_id: str, db: Session = Depends(get_db)):
    rows = AutonomyService.get_execution_results(db, verdict_id)
    return {
        "verdict_id": verdict_id,
        "count": len(rows),
        "items": [
            {
                "id": r.id,
                "status": r.status,
                "duration_ms": r.duration_ms,
                "error_code": r.error_code,
                "result_hash": r.result_hash,
                "timestamp": r.timestamp.isoformat(),
            }
            for r in rows
        ],
    }


@router.get("/evidence/{verdict_id}")
def get_ai_evidence_bundle(verdict_id: str, db: Session = Depends(get_db)):
    return build_ares_ai_evidence_bundle(db, verdict_id=verdict_id)


@router.get("/memory/{target}")
def get_ares_memory(target: str, limit: int = 20, db: Session = Depends(get_db)):
    return AutonomyService.get_ares_memory(db, target, limit=max(1, min(limit, 100)))


@router.get("/monitor/{target}")
def get_ares_monitor(target: str, limit: int = 20, db: Session = Depends(get_db)):
    return AutonomyService.get_ares_health(db, target, limit=max(1, min(limit, 100)))


@router.get("/approvals/{verdict_id}", response_model=ApprovalListResponse)
def list_approvals(verdict_id: str, db: Session = Depends(get_db)):
    rows = AutonomyService.list_approvals(db, verdict_id)
    return {
        "verdict_id": verdict_id,
        "count": len(rows),
        "items": [
            {
                "approval_id": row.approval_id,
                "verdict_id": row.verdict_id,
                "target": row.target,
                "action_type": row.action_type,
                "risk_score": row.risk_score,
                "approver": row.approver,
                "reason": row.reason,
                "signature": row.signature,
                "approved_at": row.approved_at.isoformat(),
                "recorded_at": row.recorded_at.isoformat(),
            }
            for row in rows
        ],
    }


@router.get("/audit", response_model=AuditListResponse)
def list_audit(verdict_id: str | None = None, limit: int = 50, db: Session = Depends(get_db)):
    rows = list_audit_records(db, verdict_id=verdict_id, limit=max(1, min(limit, 200)))
    return {
        "count": len(rows),
        "items": [
            {
                "record_id": row.record_id,
                "verdict_id": row.verdict_id,
                "actor": row.actor,
                "action": row.action,
                "hash_prev": row.hash_prev,
                "hash_self": row.hash_self,
                "timestamp": row.timestamp.isoformat(),
            }
            for row in rows
        ],
    }


@router.get("/audit/verify", response_model=AuditVerifyResponse)
def verify_audit(db: Session = Depends(get_db)):
    return verify_audit_chain(db)
