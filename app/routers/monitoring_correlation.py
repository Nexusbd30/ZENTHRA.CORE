from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.security import require_admin_or_monitor_token
from app.db.session import get_db
from app.models.threat_model import ThreatModel
from app.services.correlation_engine import correlation_engine

router = APIRouter(
    prefix="/monitoring/correlation",
    tags=["monitoring-correlation"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


def serialize_threat(threat: ThreatModel) -> dict:
    level = getattr(threat, "level", None)
    category = getattr(threat, "category", None)
    return {
        "id": getattr(threat, "id", None),
        "title": getattr(threat, "title", None),
        "description": getattr(threat, "description", None),
        "level": level.value if level else None,
        "category": category.value if category else None,
        "score": getattr(threat, "score", None),
        "source": getattr(threat, "source", None),
        "target_service": getattr(threat, "target_service", None),
        "fingerprint": getattr(threat, "fingerprint", None),
        "siem_metadata": getattr(threat, "siem_metadata", None),
        "created_at": getattr(threat, "created_at", None),
        "updated_at": getattr(threat, "updated_at", None),
    }


@router.post("/run")
def run_correlation(db: Session = Depends(get_db)) -> dict:
    result = correlation_engine.run_correlation(db)
    created = result.get("created_threats", []) or []
    return {
        "created_count": result.get("created_count", len(created)),
        "rules_triggered": result.get("rules_triggered", []),
        "fired_alerts": result.get("fired_alerts", []),
        "created_threats": [serialize_threat(threat) for threat in created],
        "timestamp": result.get("timestamp"),
        "updated_count": result.get("updated_count"),
        "resolved_count": result.get("resolved_count"),
    }
