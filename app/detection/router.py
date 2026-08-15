from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.security import require_admin_or_monitor_token
from app.detection.correlation import correlate_detections
from app.detection.entity_graph import build_entity_graph
from app.detection.ioc_enrichment import enrich_iocs
from app.detection.rules import BUILTIN_RULES, evaluate_rules

router = APIRouter(
    prefix="/api/v1/detection",
    tags=["detection"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


class DetectionEvaluateRequest(BaseModel):
    events: list[dict[str, Any]] = Field(default_factory=list)


@router.get("/status")
def detection_status():
    return {
        "status": "enabled",
        "schema": "vaelqorix.detection.engine.v1",
        "rule_count": len(BUILTIN_RULES),
        "capabilities": [
            "sigma_lite_rules",
            "kill_chain_mapping",
            "temporal_correlation_ready",
            "behavioral_baseline_ready",
            "ioc_enrichment",
            "entity_graph",
        ],
    }


@router.post("/evaluate")
def evaluate_detection(payload: DetectionEvaluateRequest):
    matches = evaluate_rules(payload.events)
    return {
        "status": "ok",
        "matches": matches,
        "correlation": correlate_detections(matches),
        "entity_graph": build_entity_graph(payload.events, matches),
        "ioc_enrichment": [enrich_iocs(event) for event in payload.events],
    }
