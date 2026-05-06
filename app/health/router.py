from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.health.checks import run_checks

router = APIRouter(prefix="/system", tags=["system-health"])


@router.get("/health")
def system_health(db: Session = Depends(get_db)):
    return run_checks(db)


@router.get("/ready")
def system_ready(db: Session = Depends(get_db)):
    state = run_checks(db)
    return {"status": "ready" if state["overall"] == "up" else "degraded", **state}
