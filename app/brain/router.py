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


class BrainChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    source: str = Field(default="manual", min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)
    target: str = Field(default="", max_length=255)
    risk_score: float = Field(default=50.0, ge=0, le=100)
    factors: list[str] = Field(default_factory=list, max_length=50)
    execution_controls: dict[str, Any] = Field(default_factory=dict)


def _chat_intent(message: str, payload: dict[str, Any]) -> str:
    normalized = message.lower()
    if payload or any(term in normalized for term in ("ingest", "aresx", "event", "analyze")):
        return "brain_lifecycle"
    if any(term in normalized for term in ("verdict", "redqueen", "score", "risk")):
        return "redqueen_verdict"
    return "guidance"


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


@router.post("/chat")
def chat_with_redqueen(payload: BrainChatRequest, db: Session = Depends(get_db)):
    intent = _chat_intent(payload.message, payload.payload)
    controls = {
        "dry_run": True,
        "source": "redqueen-chatbot",
        "chat_message": payload.message,
        "brain_chat": True,
        **payload.execution_controls,
    }
    controls["dry_run"] = True

    if intent == "brain_lifecycle":
        order_payload = payload.payload or {
            "id": f"chat-{abs(hash(payload.message))}",
            "description": payload.message,
            "magnitude": max(1, min(10, round(payload.risk_score / 10))),
            "target": payload.target or "chat:operator-request",
        }
        result = run_brain_lifecycle(
            BrainLifecycleRequest(
                source=payload.source,
                payload=order_payload,
                execution_controls=controls,
                human_approved=False,
            ),
            db,
        )
        return {
            "status": "ok",
            "role": "redqueen",
            "intent": intent,
            "message": "ARESX order accepted as governed dry-run. ARES execution remains operator-gated.",
            "safety_boundary": "dry_run_only",
            "result": result,
        }

    if intent == "redqueen_verdict":
        verdict = AutonomyService.issue_verdict(
            db,
            target=payload.target or "chat:operator-request",
            risk_score=payload.risk_score,
            factors=[
                *payload.factors,
                "source:redqueen_chatbot",
                "operator_chat_requested_verdict",
            ],
            execution_controls=controls,
        )
        return {
            "status": "ok",
            "role": "redqueen",
            "intent": intent,
            "message": "RedQueen verdict generated in dry-run context. Send it to ARES only through governed execution.",
            "safety_boundary": "dry_run_only",
            "result": {"verdict": verdict},
        }

    return {
        "status": "ok",
        "role": "redqueen",
        "intent": intent,
        "message": (
            "Provide owned telemetry or request a verdict. I can route ARESX events, generate "
            "RedQueen verdicts, and trigger ARES dry-run execution with audit evidence."
        ),
        "safety_boundary": "authorized_owned_telemetry_only",
        "result": {},
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
