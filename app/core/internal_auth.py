from __future__ import annotations

import secrets
from typing import Optional

from fastapi import Header, HTTPException, status

from app.core.settings import settings


def require_internal_bearer(
    authorization: Optional[str] = Header(default=None),
) -> None:
    expected = settings.ZENTHRA_MONITOR_TOKEN
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ZENTHRA_MONITOR_TOKEN no configurado en el servidor",
        )

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization Bearer requerido",
            headers={"WWW-Authenticate": "Bearer"},
        )

    provided = authorization.split(" ", 1)[1].strip()
    if not secrets.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token invalido",
        )
