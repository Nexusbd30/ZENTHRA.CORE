from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from datetime import time as datetime_time
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.ares.evidence import build_ares_ai_evidence_bundle
from app.attack_analysis.service import AttackAnalysisService
from app.core.security import require_admin_or_control_token
from app.db.audit_store import list_audit_records
from app.db.session import get_db
from app.ingestion.aresx_router import (
    AresXIngestEventRequest,
    ingest_event,
)
from app.models.execution_result import ExecutionResult
from app.models.verdict import Verdict
from app.services.autonomy_service import AutonomyService

router = APIRouter(
    prefix="/api/v1/brain",
    tags=["redqueen-brain"],
    dependencies=[Depends(require_admin_or_control_token)],
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
    evidence_terms = (
        "evidence",
        "evidencia",
        "evidencias",
        "audit",
        "auditoria",
        "auditoría",
        "pruebas",
    )
    today_terms = ("today", "hoy", "24h", "ultimas", "últimas", "recientes")
    if any(term in normalized for term in evidence_terms) and any(
        term in normalized for term in today_terms
    ):
        return "evidence_today"
    if payload or any(term in normalized for term in ("ingest", "aresx", "event", "analyze")):
        return "brain_lifecycle"
    if any(term in normalized for term in ("verdict", "redqueen", "score", "risk")):
        return "redqueen_verdict"
    return "guidance"


def _safe_json(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def _today_utc_start() -> datetime:
    return datetime.combine(datetime.now(UTC).date(), datetime_time.min, tzinfo=UTC).replace(
        tzinfo=None
    )


def _evidence_today(db: Session, *, limit: int = 10) -> dict[str, Any]:
    start = _today_utc_start()
    verdict_rows = list(
        db.scalars(
            select(Verdict)
            .where(Verdict.timestamp >= start)
            .order_by(desc(Verdict.timestamp))
            .limit(limit)
        ).all()
    )
    execution_rows = list(
        db.scalars(
            select(ExecutionResult)
            .where(ExecutionResult.timestamp >= start)
            .order_by(desc(ExecutionResult.timestamp))
            .limit(limit)
        ).all()
    )
    audit_rows = [
        row for row in list_audit_records(db, limit=max(limit, 50)) if row.timestamp >= start
    ][:limit]

    bundles = []
    for verdict in verdict_rows[:3]:
        bundles.append(build_ares_ai_evidence_bundle(db, verdict_id=verdict.verdict_id))

    return {
        "schema": "vaelqorix.brain.evidence_today.v1",
        "since_utc": start.isoformat() + "Z",
        "counts": {
            "verdicts": len(verdict_rows),
            "executions": len(execution_rows),
            "audit_records": len(audit_rows),
            "evidence_bundles": len(bundles),
        },
        "verdicts": [
            {
                "verdict_id": row.verdict_id,
                "timestamp": row.timestamp.isoformat() + "Z",
                "target": row.target,
                "status": row.status,
                "action_type": row.action_type,
                "risk_score": row.risk_score,
                "confidence": row.confidence,
                "requires_human": row.requires_human,
                "factors": _safe_json(row.factors, []),
                "signature": row.signature,
            }
            for row in verdict_rows
        ],
        "executions": [
            {
                "id": row.id,
                "verdict_id": row.verdict_id,
                "timestamp": row.timestamp.isoformat() + "Z",
                "action_type": row.action_type,
                "target_entity": row.target_entity,
                "target_system": row.target_system,
                "status": row.status,
                "duration_ms": row.duration_ms,
                "result_hash": row.result_hash,
                "evidence": _safe_json(row.evidence, []),
            }
            for row in execution_rows
        ],
        "audit": [
            {
                "record_id": row.record_id,
                "verdict_id": row.verdict_id,
                "timestamp": row.timestamp.isoformat() + "Z",
                "actor": row.actor,
                "action": row.action,
                "hash_self": row.hash_self,
            }
            for row in audit_rows
        ],
        "bundles": bundles,
    }


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

    if intent == "evidence_today":
        result = _evidence_today(db)
        counts = result["counts"]
        return {
            "status": "ok",
            "role": "redqueen",
            "intent": intent,
            "message": (
                f"Evidencias de hoy listas: {counts['verdicts']} verdicts, "
                f"{counts['executions']} ejecuciones, {counts['audit_records']} registros de auditoria "
                f"y {counts['evidence_bundles']} bundles ARES."
            ),
            "safety_boundary": "authorized_owned_telemetry_only",
            "result": result,
        }

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
