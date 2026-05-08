from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.ares.approval import build_approval_payload
from app.ares.kill_switch import kill_switch_state
from app.core.security import require_admin_or_monitor_token
from app.db.audit_store import list_audit_records, verify_audit_chain
from app.db.session import get_db
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
    dependencies=[Depends(require_admin_or_monitor_token)],
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


class ApprovalRequest(BaseModel):
    verdict: dict
    approver: str = Field(..., min_length=1)
    reason: str = ""


@router.get("/status", response_model=AresStatusResponse)
def ares_status():
    return {
        "module": "ares",
        "role": "executor",
        "phase": "phase-2-core",
        "kill_switch": kill_switch_state(),
    }


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
                "label": "RedQueen causal verdict",
                "endpoint": "/api/v1/redqueen/verdict/from-threat/{threat_id}",
                "owner": "redqueen",
                "ui_surface": "RedQueen Brain",
                "produces": ["verdict_id", "risk_score", "action_type", "justification_xai"],
            },
            {
                "key": "ares_plan",
                "label": "ARES validation and execution plan",
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
            "Disruptive actions require traceability and may require signed human approval.",
        ],
    }


@router.post("/execute")
def execute_verdict(payload: ExecuteRequest, db: Session = Depends(get_db)):
    return AutonomyService.execute_verdict(
        db,
        verdict=payload.verdict,
        human_approved=payload.human_approved,
        approval_evidence=payload.approval_evidence,
    )


@router.post("/approval-token")
def create_approval_token(payload: ApprovalRequest):
    return build_approval_payload(
        verdict=payload.verdict,
        approver=payload.approver,
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
