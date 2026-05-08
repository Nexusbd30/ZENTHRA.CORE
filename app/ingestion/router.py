from __future__ import annotations

from datetime import datetime
from typing import Any, cast

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.security import require_admin_or_monitor_token
from app.db.session import get_db
from app.ingestion.normalizer import normalize_event
from app.models.threat_model import ThreatModel

router = APIRouter(
    prefix="/api/v1/ingestion",
    tags=["ingestion"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


class IngestEventRequest(BaseModel):
    source: str | None = None
    event: dict[str, Any] = Field(default_factory=dict)
    labels: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] = Field(default_factory=dict)
    title: str | None = None
    description: str | None = None
    alertname: str | None = None
    severity: str | None = None
    category: str | None = None
    score: int | None = Field(default=None, ge=0, le=100)
    target: str | None = None
    target_service: str | None = None
    source_ip: str | None = None
    database_name: str | None = None
    database_host: str | None = None
    fingerprint: str | None = None
    first_seen_at: str | None = None
    last_seen_at: str | None = None
    status: str | None = None
    state: str | None = None
    value: str | None = None


def _upsert_threat(db: Session, normalized: dict[str, Any]) -> tuple[ThreatModel, bool]:
    fingerprint = str(normalized["fingerprint"])
    existing = db.query(ThreatModel).filter(ThreatModel.fingerprint == fingerprint).first()
    if existing:
        metadata: dict[str, Any] = (
            dict(existing.siem_metadata) if isinstance(existing.siem_metadata, dict) else {}
        )
        incoming = normalized["siem_metadata"]
        metadata["status"] = incoming.get("status", metadata.get("status", "open"))
        metadata["last_seen_at"] = incoming.get("last_seen_at")
        metadata["occurrences"] = int(metadata.get("occurrences", 0) or 0) + 1
        metadata["evidence"] = incoming.get("evidence", metadata.get("evidence", {}))
        existing.title = normalized["title"]
        existing.description = normalized["description"]
        existing.level = normalized["level"]
        existing.category = normalized["category"]
        existing.score = normalized["score"]
        existing.target_service = normalized["target_service"]
        existing.source_ip = normalized["source_ip"]
        existing.database_name = normalized["database_name"]
        existing.database_host = normalized["database_host"]
        mutable_existing = cast(Any, existing)
        mutable_existing.siem_metadata = metadata
        mutable_existing.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(existing)
        return existing, False

    threat = ThreatModel(**normalized)
    db.add(threat)
    db.commit()
    db.refresh(threat)
    return threat, True


@router.get("/status")
def ingestion_status():
    return {
        "module": "ingestion",
        "phase": "phase-2-normalizer",
        "status": "ready",
        "inputs": ["siem", "edr", "iam", "netflow", "prometheus"],
        "dedupe": "fingerprint",
    }


@router.post("/events")
def ingest_event(payload: IngestEventRequest, db: Session = Depends(get_db)):
    normalized = normalize_event(payload.model_dump(exclude_none=True))
    threat, created = _upsert_threat(db, normalized)
    return {
        "status": "created" if created else "updated",
        "threat_id": threat.id,
        "fingerprint": threat.fingerprint,
        "occurrences": (
            threat.siem_metadata.get("occurrences", 1)
            if isinstance(threat.siem_metadata, dict)
            else 1
        ),
        "threat": threat.to_dict(),
    }


@router.post("/normalize")
def normalize_only(payload: IngestEventRequest):
    normalized = normalize_event(payload.model_dump(exclude_none=True))
    return {
        **normalized,
        "level": normalized["level"].value,
        "category": normalized["category"].value,
    }
