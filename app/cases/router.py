from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.cases.service import create_case
from app.core.security import require_admin_or_monitor_token

router = APIRouter(
    prefix="/api/v1/cases",
    tags=["cases"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


class CaseCreateRequest(BaseModel):
    title: str = Field(..., min_length=1)
    severity: str = "high"
    tenant_id: str = Field(default="default", min_length=1)
    verdict: dict[str, Any] = Field(default_factory=dict)
    legal_pack: dict[str, Any] = Field(default_factory=dict)


@router.post("")
def create_case_endpoint(payload: CaseCreateRequest):
    return create_case(
        title=payload.title,
        severity=payload.severity,
        tenant_id=payload.tenant_id,
        verdict=payload.verdict,
        legal_pack=payload.legal_pack,
    )
