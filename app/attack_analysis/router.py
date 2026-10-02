from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.attack_analysis.service import AttackAnalysisService
from app.core.security import require_admin_or_control_token
from app.db.session import get_db

router = APIRouter(
    prefix="/api/v1/attack-analysis",
    tags=["attack-analysis"],
    dependencies=[Depends(require_admin_or_control_token)],
)


class VerdictFromAnalysisRequest(BaseModel):
    execution_controls: dict = Field(default_factory=dict)


@router.get("/status")
def attack_analysis_status():
    return {
        "module": "attack_analysis",
        "status": "enabled",
        "schema": "vaelqorix.attack_analysis.v1",
        "capabilities": [
            "timeline_reconstruction",
            "attack_reality_classification",
            "false_positive_signals",
            "causal_chain",
            "redqueen_verdict_from_analysis",
        ],
    }


@router.get("/entities")
def list_attack_analyses(
    entity_id: str | None = None,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    return AttackAnalysisService.list_analyses(db, entity_id=entity_id, limit=limit)


@router.get("/entities/{entity_id}")
def analyze_entity(entity_id: str, limit: int = 100, db: Session = Depends(get_db)):
    return AttackAnalysisService.analyze_entity(db, entity_id=entity_id, limit=limit)


@router.post("/entities/{entity_id}/verdict")
def issue_verdict_from_analysis(
    entity_id: str,
    payload: VerdictFromAnalysisRequest | None = None,
    db: Session = Depends(get_db),
):
    payload = payload or VerdictFromAnalysisRequest()
    return AttackAnalysisService.issue_verdict_from_analysis(
        db,
        entity_id=entity_id,
        execution_controls=payload.execution_controls,
    )
