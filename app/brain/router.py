from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.attack_analysis.service import AttackAnalysisService
from app.core.security import require_admin_or_monitor_token
from app.db.session import get_db
from app.ingestion.aresx_router import (
    AresXIngestEventRequest,
    ingest_event,
)
from app.services.autonomy_service import AutonomyService

router = APIRouter(
    prefix="/api/v1/brain",
    tags=["redqueen-brain"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


class BrainLifecycleRequest(BaseModel):
    source: str = Field(..., min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)
    execution_controls: dict[str, Any] = Field(default_factory=dict)
    human_approved: bool = False
    approval_evidence: dict[str, Any] | None = None


@router.get("/status")
def brain_status():
    return {
        "module": "redqueen_brain",
        "schema": "vaelqorix.brain.lifecycle.v1",
        "status": "enabled",
        "chain": [
            "aresx_ingest",
            "attack_analysis",
            "redqueen_verdict",
            "ares_validation",
            "ares_dry_run_execution",
            "evidence",
        ],
        "default_execution_mode": "dry_run",
        "safety_boundary": "authorized_owned_telemetry_only",
    }


@router.post("/lifecycle")
def run_brain_lifecycle(payload: BrainLifecycleRequest, db: Session = Depends(get_db)):
    start = time.perf_counter()
    controls = {
        "dry_run": True,
        "source": "redqueen-brain",
        "brain_lifecycle": True,
        **payload.execution_controls,
    }
    controls["dry_run"] = True

    ingest = ingest_event(
        AresXIngestEventRequest(source=payload.source, payload=payload.payload),
        db,
    )
    analysis = AttackAnalysisService.analyze_entity(db, entity_id=str(ingest["entity_id"]))
    verdict_response = AttackAnalysisService.issue_verdict_from_analysis(
        db,
        entity_id=str(ingest["entity_id"]),
        execution_controls={
            **controls,
            "aresx_event_id": ingest["aresx_id"],
            "source_event_id": ingest["event_id"],
        },
    )
    verdict = verdict_response.get("verdict", {})
    execution = (
        AutonomyService.execute_verdict(
            db,
            verdict=verdict,
            human_approved=True if controls.get("dry_run") else payload.human_approved,
            approval_evidence=payload.approval_evidence,
        )
        if verdict
        else {"status": "skipped", "reason": "verdict_not_available"}
    )

    return {
        "status": "completed",
        "schema": "vaelqorix.brain.lifecycle.v1",
        "mode": "dry_run",
        "elapsed_ms": round((time.perf_counter() - start) * 1000, 2),
        "ingest": ingest,
        "analysis": analysis,
        "verdict": verdict,
        "execution": execution,
    }
