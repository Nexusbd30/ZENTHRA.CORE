from __future__ import annotations

from fastapi import APIRouter, Depends

from app.compliance.controls import compliance_evidence_snapshot
from app.core.security import require_admin_or_monitor_token

router = APIRouter(
    prefix="/api/v1/compliance",
    tags=["compliance"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


@router.get("/evidence")
def read_compliance_evidence():
    return compliance_evidence_snapshot(
        {
            "redqueen": "enabled",
            "ares": "enabled",
            "active_defense": "enabled",
            "audit_chain": "enabled",
        }
    )
