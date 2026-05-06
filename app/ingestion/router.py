from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/ingestion", tags=["ingestion"])


@router.get("/status")
def ingestion_status():
    return {
        "module": "ingestion",
        "phase": "phase-1-stub",
        "status": "ready",
        "next": ["kafka_consumer", "normalizer", "qradar_adapter"],
    }
