from __future__ import annotations

import asyncio
import logging

import httpx
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.security import require_admin_or_monitor_token
from app.core.settings import settings
from app.db.session import get_db

logger = logging.getLogger("vaelqorix.health")
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

    async def check_component(name: str, url: str) -> str:
        try:
            async with httpx.AsyncClient(timeout=1.0) as client:
                response = await client.get(url)
            return "up" if response.status_code == 200 else "down"
        except Exception as e:  # noqa: BLE001
            logger.warning("%s health check failed: %r", name, e)
            return "down"

    prom_url = settings.PROMETHEUS_BASE.rstrip("/") + "/-/ready"
    alertmanager_url = settings.ALERTMANAGER_BASE.rstrip("/") + "/-/ready"
    status["prometheus"], status["alertmanager"] = await asyncio.gather(
        check_component("Prometheus", prom_url),
        check_component("Alertmanager", alertmanager_url),
    )

    up_components = [
        key for key, value in status.items() if key != "overall" and value == "up"
    ]
    if len(up_components) >= 3:
        status["overall"] = "up"
    elif len(up_components) >= 2:
        status["overall"] = "degraded"

    return status
