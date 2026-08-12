from __future__ import annotations

from fastapi import APIRouter, Depends, Header
from sqlalchemy.orm import Session

from app.core.security import require_admin_or_monitor_token
from app.db.session import get_db
from app.platform.schemas import PlatformMapResponse, PlatformReadinessResponse
from app.platform.service import build_platform_map, build_platform_readiness

router = APIRouter(
    prefix="/api/v1/platform",
    tags=["vaelqorix-platform"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


@router.get("/map", response_model=PlatformMapResponse)
def platform_map():
    return build_platform_map()


@router.get("/readiness", response_model=PlatformReadinessResponse)
def platform_readiness(
    x_tenant_id: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    return build_platform_readiness(db, tenant_id=x_tenant_id)

