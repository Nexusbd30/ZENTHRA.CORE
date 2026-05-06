from __future__ import annotations

from fastapi import Depends, Header, Request
from sqlalchemy.orm import Session

from app.core.security import get_current_active_user
from app.db.session import get_db


def get_db_session(db: Session = Depends(get_db)) -> Session:
    return db


def get_actor(current_user=Depends(get_current_active_user)):
    return current_user


def get_request_id(request: Request, x_request_id: str | None = Header(default=None)) -> str:
    return x_request_id or request.headers.get("x-request-id") or "n/a"
