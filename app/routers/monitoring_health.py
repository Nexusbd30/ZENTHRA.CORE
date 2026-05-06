from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.security import require_admin_or_monitor_token
from app.core.settings import settings
from app.db.session import get_db

logger = logging.getLogger("zenthra.health")
router = APIRouter(prefix="/monitoring", tags=["monitoring"])


@router.get("/health/full")
async def health_full(
    db: Session = Depends(get_db),
    _: None = Depends(require_admin_or_monitor_token),
):
    status = {
        "backend": "up",
        "database": "down",
        "prometheus": "down",
        "alertmanager": "down",
        "overall": "down",
    }

    try:
        db.execute(text("SELECT 1"))
        status["database"] = "up"
    except Exception as e:  # noqa: BLE001
        logger.error("DB health check failed: %r", e)

    try:
        prom_url = settings.PROMETHEUS_BASE.rstrip("/") + "/-/ready"
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(prom_url)
        status["prometheus"] = "up" if response.status_code == 200 else "down"
    except Exception as e:  # noqa: BLE001
        logger.warning("Prometheus health check failed: %r", e)

    try:
        alertmanager_url = settings.ALERTMANAGER_BASE.rstrip("/") + "/-/ready"
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(alertmanager_url)
        status["alertmanager"] = "up" if response.status_code == 200 else "down"
    except Exception as e:  # noqa: BLE001
        logger.warning("Alertmanager health check failed: %r", e)

    up_components = [
        key for key, value in status.items() if key != "overall" and value == "up"
    ]
    if len(up_components) >= 3:
        status["overall"] = "up"
    elif len(up_components) >= 2:
        status["overall"] = "degraded"

    return status
