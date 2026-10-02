from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.control.capabilities import autonomy_capability_map
from app.control.maturity import ares_maturity, autonomy_control_maturity, redqueen_maturity
from app.core.security import require_admin_or_control_token
from app.db.session import get_db

router = APIRouter(
    prefix="/api/v1/control",
    tags=["control"],
    dependencies=[Depends(require_admin_or_control_token)],
)


@router.get("/maturity")
def get_maturity(db: Session = Depends(get_db)):
    return autonomy_control_maturity(db)


@router.get("/maturity/redqueen")
def get_redqueen_maturity(db: Session = Depends(get_db)):
    return redqueen_maturity(db)


@router.get("/maturity/ares")
def get_ares_maturity(db: Session = Depends(get_db)):
    return ares_maturity(db)


@router.get("/capabilities")
def get_capabilities():
    return autonomy_capability_map()
