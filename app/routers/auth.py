# ==============================================================
# 🔐 AUTH ROUTER — ZENTHRA.CORE_SECURITY (v4.1 RBAC JWT)
# ==============================================================
# Modo JSON completo:
#   POST /auth/login
#
# Cambios v4.1:
#   - El JWT ahora incluye el rol del usuario (RBAC)
#   - Compatible con require_roles() en security.py
# ==============================================================

import time
from datetime import timedelta
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.security import create_access_token
from app.core.settings import settings
from app.db.session import get_db
from app.schemas.auth_schema import LoginRequest, TokenResponse
from app.services.user_service import UserService

router = APIRouter(prefix="/auth", tags=["auth"])

# ==============================================================
# 🛡️ ANTI BRUTE-FORCE / RATE LIMIT POR IP
# ==============================================================

_FAILED_LOGINS: Dict[str, List[float]] = {}

MAX_ATTEMPTS_PER_WINDOW = 5
BLOCK_WINDOW_SEC = 15 * 60  # 15 minutos


def _register_failed_attempt(ip: str) -> None:
    now = time.time()
    attempts = _FAILED_LOGINS.get(ip, [])
    attempts = [ts for ts in attempts if now - ts < BLOCK_WINDOW_SEC]
    attempts.append(now)
    _FAILED_LOGINS[ip] = attempts


def _is_ip_blocked(ip: str) -> bool:
    now = time.time()
    attempts = _FAILED_LOGINS.get(ip, [])
    attempts = [ts for ts in attempts if now - ts < BLOCK_WINDOW_SEC]
    _FAILED_LOGINS[ip] = attempts
    return len(attempts) >= MAX_ATTEMPTS_PER_WINDOW


# ==============================================================
# 🔑 LOGIN — JSON + JWT + RBAC
# ==============================================================

@router.post("/login", response_model=TokenResponse)
def login(
    user: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Autenticación de usuario.

    - Verifica credenciales
    - Aplica rate-limit por IP
    - Devuelve JWT con:
        · sub  (email)
        · role (admin | analyst | viewer)
    """

    client_ip = request.client.host if request.client else "unknown"

    # 1️⃣ Anti brute-force
    if _is_ip_blocked(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos fallidos. Intenta de nuevo más tarde.",
        )

    # 2️⃣ Buscar usuario
    db_user = UserService.get_user_by_email(db, user.username)

    # 3️⃣ Verificar contraseña
    if not db_user or not UserService.verify_password(
        user.password, db_user.hashed_password
    ):
        _register_failed_attempt(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4️⃣ Limpiar contador si login OK
    _FAILED_LOGINS.pop(client_ip, None)

    # 5️⃣ Expiración
    expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    # 6️⃣ JWT CON ROL (CAMBIO CLAVE)
    token = create_access_token(
        data={
            "sub": db_user.email,
            "role": db_user.role,  # 👈 RBAC
        },
        expires_delta=expires,
    )

    return {
        "access_token": token,
        "token_type": "bearer",
    }
