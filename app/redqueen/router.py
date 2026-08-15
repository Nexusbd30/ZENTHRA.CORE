from __future__ import annotations

import json

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.security import require_admin_or_monitor_token
from app.core.settings import settings
from app.db.session import get_db
from app.db.vector import vector_store
from app.models.entity_profile import EntityProfile
from app.models.verdict import Verdict
from app.redqueen.anticipation import anticipate_attack_path
from app.redqueen.mission import build_thinking_model
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


class ThreatEventVerdictRequest(BaseModel):
    execution_controls: dict = Field(default_factory=dict)


class VectorMemoryRequest(BaseModel):
    collection: str = Field(default="redqueen-memory", min_length=1)
    record_id: str = Field(..., min_length=1)
    text: str = Field(..., min_length=1)
    metadata: dict = Field(default_factory=dict)


class AnticipationRequest(BaseModel):
    target: str = Field(..., min_length=1)
    risk_score: float = Field(..., ge=0, le=100)
    factors: list[str] = Field(default_factory=list)
    execution_controls: dict = Field(default_factory=dict)


def _json_loads(value: str | None, fallback):
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def _verdict_payload(verdict: Verdict) -> dict:
    return {
        "verdict_id": verdict.verdict_id,
        "threat_event_id": verdict.threat_event_id,
        "status": verdict.status,
        "severity": verdict.severity,
        "timestamp": verdict.timestamp.isoformat(),
        "target": verdict.target,
        "action_type": verdict.action_type,
        "primary_action": verdict.primary_action or verdict.action_type,
        "recommended_actions": _json_loads(verdict.recommended_actions, []),
        "risk_score": verdict.risk_score,
        "confidence": verdict.confidence,
        "confidence_score": verdict.confidence_score or verdict.confidence,
        "xai_explanation": _json_loads(verdict.xai_explanation, {}),
        "requires_human": verdict.requires_human,
        "requires_human_approval": verdict.requires_human_approval or verdict.requires_human,
        "policy_rule": verdict.policy_rule,
        "ttl_seconds": verdict.ttl_seconds,
        "expires_at": verdict.expires_at.isoformat() if verdict.expires_at else None,
    }


@router.get("/status", response_model=RedQueenStatusResponse)
def redqueen_status():
    return {
        "module": "redqueen",
        "role": "autonomous_defense_brain",
        "phase": "phase-2-core",
        "autonomy_target": int(settings.REDQUEEN_AUTONOMY_MAX),
        "thinking_model": build_thinking_model(risk_score=0.0),
        "attack_anticipation": {
            "schema": "vaelqorix.redqueen.attack_anticipation.v1",
            "status": "enabled",
            "purpose": "anticipate_attack_paths_for_business_infrastructure_defense",
        },
    }


@router.post("/policy/evaluate", response_model=PolicyEvaluationResponse)
def policy_evaluate(score: float, action_type: str):
    return evaluate_policy(score=score, action_type=action_type)


@router.post("/anticipate")
def anticipate_attack(payload: AnticipationRequest):
    return anticipate_attack_path(
        target=payload.target,
        risk_score=payload.risk_score,
        factors=payload.factors,
        controls=payload.execution_controls,
    )


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


@router.post("/verdict/from-event/{event_id}")
def issue_verdict_from_threat_event(
    event_id: str,
    payload: ThreatEventVerdictRequest | None = None,
    db: Session = Depends(get_db),
):
    payload = payload or ThreatEventVerdictRequest()
    return AutonomyService.issue_verdict_from_threat_event(
        db,
        event_id=event_id,
        execution_controls=payload.execution_controls,
    )


@router.get("/verdicts")
def list_verdicts(
    status: str | None = None,
    target: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    query = select(Verdict).order_by(desc(Verdict.timestamp)).limit(max(1, min(limit, 200)))
    if status:
        query = query.where(Verdict.status == status)
    if target:
        query = query.where(Verdict.target == target)
    rows = list(db.scalars(query).all())
    return {
        "count": len(rows),
        "items": [_verdict_payload(row) for row in rows],
    }


@router.get("/verdicts/{verdict_id}")
def read_aresx_verdict(verdict_id: str, db: Session = Depends(get_db)):
    verdict = db.get(Verdict, verdict_id)
    if not verdict:
        return {"status": "not_found", "verdict_id": verdict_id}
    return _verdict_payload(verdict)


@router.post("/verdicts/{verdict_id}/approve")
def approve_aresx_verdict(verdict_id: str, db: Session = Depends(get_db)):
    verdict = db.get(Verdict, verdict_id)
    if not verdict:
        return {"status": "not_found", "verdict_id": verdict_id}
    verdict.status = "approved"
    verdict.requires_human = False
    verdict.requires_human_approval = False
    db.add(verdict)
    db.commit()
    db.refresh(verdict)
    return _verdict_payload(verdict)


@router.post("/verdicts/{verdict_id}/reject")
def reject_aresx_verdict(verdict_id: str, db: Session = Depends(get_db)):
    verdict = db.get(Verdict, verdict_id)
    if not verdict:
        return {"status": "not_found", "verdict_id": verdict_id}
    verdict.status = "rejected"
    db.add(verdict)
    db.commit()
    db.refresh(verdict)
    return _verdict_payload(verdict)


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


@router.get("/entities/{entity_id}/profile")
def read_entity_profile(entity_id: str, db: Session = Depends(get_db)):
    profile = db.get(EntityProfile, entity_id)
    if not profile:
        return {"status": "not_found", "entity_id": entity_id}
    return {
        "entity_id": profile.entity_id,
        "entity_type": profile.entity_type,
        "baseline_vector": _json_loads(profile.baseline_vector, []),
        "feature_stats": _json_loads(profile.feature_stats, {}),
        "anomaly_score": profile.anomaly_score,
        "risk_score": profile.risk_score,
        "risk_level": profile.risk_level,
        "last_seen": profile.last_seen.isoformat(),
        "risk_factors": _json_loads(profile.risk_factors, []),
        "observed_mitre_tags": _json_loads(profile.observed_mitre_tags, []),
        "is_whitelisted": profile.is_whitelisted,
        "whitelist_reason": profile.whitelist_reason,
        "event_count": profile.event_count,
    }


@router.get("/stats")
def read_redqueen_stats(db: Session = Depends(get_db)):
    total_verdicts = db.scalar(select(func.count()).select_from(Verdict)) or 0
    pending = db.scalar(select(func.count()).select_from(Verdict).where(Verdict.status == "pending")) or 0
    approved = (
        db.scalar(select(func.count()).select_from(Verdict).where(Verdict.status == "approved"))
        or 0
    )
    rejected = (
        db.scalar(select(func.count()).select_from(Verdict).where(Verdict.status == "rejected"))
        or 0
    )
    human_required = (
        db.scalar(
            select(func.count()).select_from(Verdict).where(Verdict.requires_human_approval.is_(True))
        )
        or 0
    )
    return {
        "total_verdicts": total_verdicts,
        "pending": pending,
        "approved": approved,
        "rejected": rejected,
        "human_required": human_required,
    }


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
