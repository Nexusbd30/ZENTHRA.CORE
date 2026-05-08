from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.security import require_admin_or_monitor_token
from app.db.session import get_db
from app.db.vector import vector_store
from app.redqueen.policy_matrix import evaluate_policy
from app.schemas.autonomy_schema import (
    NotFoundResponse,
    PolicyEvaluationResponse,
    RedQueenStatusResponse,
    VerdictReadResponse,
)
from app.services.autonomy_service import AutonomyService

router = APIRouter(
    prefix="/api/v1/redqueen",
    tags=["redqueen"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


class VerdictRequest(BaseModel):
    target: str = Field(..., min_length=1)
    risk_score: float = Field(..., ge=0, le=100)
    factors: list[str] = Field(default_factory=list)
    execution_controls: dict = Field(default_factory=dict)


class ThreatVerdictRequest(BaseModel):
    execution_controls: dict = Field(default_factory=dict)


class VectorMemoryRequest(BaseModel):
    collection: str = Field(default="redqueen-memory", min_length=1)
    record_id: str = Field(..., min_length=1)
    text: str = Field(..., min_length=1)
    metadata: dict = Field(default_factory=dict)


@router.get("/status", response_model=RedQueenStatusResponse)
def redqueen_status():
    return {
        "module": "redqueen",
        "role": "brain",
        "phase": "phase-2-core",
        "autonomy_target": 90,
    }


@router.post("/policy/evaluate", response_model=PolicyEvaluationResponse)
def policy_evaluate(score: float, action_type: str):
    return evaluate_policy(score=score, action_type=action_type)


@router.post("/verdict")
def issue_verdict(payload: VerdictRequest, db: Session = Depends(get_db)):
    return AutonomyService.issue_verdict(
        db,
        target=payload.target,
        risk_score=payload.risk_score,
        factors=payload.factors,
        execution_controls=payload.execution_controls,
    )


@router.post("/verdict/from-threat/{threat_id}")
def issue_verdict_from_threat(
    threat_id: str,
    payload: ThreatVerdictRequest | None = None,
    db: Session = Depends(get_db),
):
    payload = payload or ThreatVerdictRequest()
    return AutonomyService.issue_verdict_from_threat(
        db,
        threat_id=threat_id,
        execution_controls=payload.execution_controls,
    )


@router.get("/verdict/{verdict_id}", response_model=VerdictReadResponse | NotFoundResponse)
def read_verdict(verdict_id: str, db: Session = Depends(get_db)):
    verdict = AutonomyService.get_verdict(db, verdict_id)
    if not verdict:
        return {"status": "not_found", "verdict_id": verdict_id}

    return {
        "verdict_id": verdict.verdict_id,
        "timestamp": verdict.timestamp.isoformat(),
        "target": verdict.target,
        "action_type": verdict.action_type,
        "risk_score": verdict.risk_score,
        "confidence": verdict.confidence,
        "policy_check": verdict.policy_check,
        "requires_human": verdict.requires_human,
    }


@router.get("/memory/{target}")
def read_risk_memory(target: str, limit: int = 10, db: Session = Depends(get_db)):
    return AutonomyService.get_risk_memory(db, target=target, limit=limit)


@router.get("/drift/{target}")
def read_risk_drift(
    target: str,
    current_score: float | None = None,
    limit: int = 10,
    db: Session = Depends(get_db),
):
    return AutonomyService.get_risk_drift(
        db,
        target=target,
        current_score=current_score,
        limit=limit,
    )


@router.get("/training/report")
def read_training_report(limit: int = 100, db: Session = Depends(get_db)):
    return AutonomyService.get_training_report(db, limit=max(1, min(limit, 500)))


@router.get("/vector/status")
def read_vector_status():
    return vector_store.status()


@router.post("/vector/upsert")
def upsert_vector_memory(payload: VectorMemoryRequest):
    record = vector_store.upsert(
        collection=payload.collection,
        record_id=payload.record_id,
        text=payload.text,
        metadata=payload.metadata,
    )
    return {
        "status": "ok",
        "collection": payload.collection,
        "record_id": record.id,
        "dimensions": len(record.vector),
    }


@router.get("/vector/search")
def search_vector_memory(collection: str = "redqueen-memory", q: str = "", limit: int = 5):
    return {
        "collection": collection,
        "query": q,
        "items": vector_store.search(collection=collection, query=q, limit=limit),
    }
