from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.ares.kill_switch import kill_switch_state
from app.core.security import require_admin_or_monitor_token
from app.db.session import get_db
from app.services.autonomy_service import AutonomyService

router = APIRouter(
    prefix="/api/v1/ares",
    tags=["ares"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


class ExecuteRequest(BaseModel):
    verdict: dict
    human_approved: bool = False


class LifecycleRequest(BaseModel):
    target: str = Field(..., min_length=1)
    risk_score: float = Field(..., ge=0, le=100)
    factors: list[str] = Field(default_factory=list)
    execution_controls: dict = Field(default_factory=dict)
    human_approved: bool = False


class ThreatLifecycleRequest(BaseModel):
    execution_controls: dict = Field(default_factory=dict)
    human_approved: bool = False


@router.get("/status")
def ares_status():
    return {
        "module": "ares",
        "role": "executor",
        "phase": "phase-2-core",
        "kill_switch": kill_switch_state(),
    }


@router.post("/kill-switch/{mode}")
def set_kill_switch(mode: str):
    mode = mode.lower().strip()
    if mode not in {"on", "off"}:
        return {"status": "error", "detail": "mode must be on/off"}
    from app.ares.kill_switch import set_kill_switch

    set_kill_switch(mode == "on")
    return {"status": "ok", "kill_switch": kill_switch_state()}


@router.post("/execute")
def execute_verdict(payload: ExecuteRequest, db: Session = Depends(get_db)):
    return AutonomyService.execute_verdict(
        db,
        verdict=payload.verdict,
        human_approved=payload.human_approved,
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
    )

    return {
        **verdict_response,
        "execution": execution_response,
    }


@router.get("/results/{verdict_id}")
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
