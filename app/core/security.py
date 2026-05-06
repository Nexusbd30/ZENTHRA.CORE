# =============================================================
# 🧠 ZENTHRA.CORE_SECURITY — Security Module (v2.8 RBAC Hardened)
# =============================================================
# Módulo central de seguridad JWT en modo JSON.
#
# Proporciona:
#   - create_access_token(data, expires_delta)
#   - get_bearer_token(authorization)
#   - get_current_user(token, db)
#   - get_current_active_user(...)
#   - get_current_admin(...)
#   - require_roles(*roles)   👈 NUEVO
#   - verify_password(plain, hashed)
#   - get_password_hash(password)
# =============================================================

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, Header, HTTPException, status
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.settings import settings
from app.db.session import get_db
from app.services.user_service import UserService

# =============================================================
# ⚙️ CONFIGURACIÓN DEL TOKEN
# =============================================================

ALGORITHM = "HS256"


# =============================================================
# 🔐 CONTEXTO DE HASH DE CONTRASEÑAS
# =============================================================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica que una contraseña en texto plano coincide con el hash guardado."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Genera un hash seguro para almacenar en la base de datos."""
    return pwd_context.hash(password)


# =============================================================
# 🔐 CREACIÓN DEL TOKEN JWT
# =============================================================

def create_access_token(
    data: dict,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Genera un token JWT firmado digitalmente.

    data puede incluir:
      - sub: email
      - role: admin | analyst | viewer
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})

    secret = settings.SECRET_KEY
    if hasattr(secret, "get_secret_value"):
        secret = secret.get_secret_value()

    return jwt.encode(to_encode, secret, algorithm=ALGORITHM)


# =============================================================
# 🧩 EXTRACCIÓN DEL TOKEN DESDE EL HEADER
# =============================================================

def get_bearer_token(authorization: str = Header(None)) -> str:
    """
    Extrae el token JWT del encabezado Authorization.
    Espera: Authorization: Bearer <token>
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return authorization.split(" ", 1)[1].strip()


# =============================================================
# 👤 OBTENER USUARIO AUTENTICADO (BÁSICO)
# =============================================================

def get_current_user(
    token: str = Depends(get_bearer_token),
    db: Session = Depends(get_db),
):
    """Valida el JWT y devuelve el usuario asociado."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudo validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        secret = settings.SECRET_KEY
        if hasattr(secret, "get_secret_value"):
            secret = secret.get_secret_value()

        payload = jwt.decode(token, secret, algorithms=[ALGORITHM])
        email: str | None = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError as err:
        raise credentials_exception from err

    user = UserService.get_user_by_email(db, email=email)
    if user is None:
        raise credentials_exception

    return user


# =============================================================
# ✅ USUARIO ACTIVO OBLIGATORIO
# =============================================================

def get_current_active_user(
    current_user=Depends(get_current_user),
):
    """Exige que el usuario esté activo."""
    if hasattr(current_user, "is_active") and not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuario inactivo. Contacta con el administrador.",
        )
    return current_user


# =============================================================
# 👑 USUARIO ADMIN (COMPATIBILIDAD)
# =============================================================

def get_current_admin(
    current_user=Depends(get_current_active_user),
):
    """Exige rol administrador."""
    role = getattr(current_user, "role", None)
    if role not in ("admin", "administrator", "superadmin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permisos insuficientes. Requiere rol administrador.",
        )
    return current_user


# =============================================================
# 🔐 RBAC FLEXIBLE (NUEVO — PRODUCCIÓN)
# =============================================================

def require_roles(*allowed_roles: str):
    """
    Dependency reutilizable para proteger endpoints por rol.

    Uso:
      Depends(require_roles("admin"))
      Depends(require_roles("admin", "analyst"))
    """

    def role_checker(
        current_user=Depends(get_current_active_user),
    ):
        role = getattr(current_user, "role", None)
        if role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permisos insuficientes para este recurso.",
            )
        return current_user

    return role_checker


def require_admin_or_monitor_token(
    authorization: str = Header(None),
    db: Session = Depends(get_db),
):
    """
    Allows either the internal monitoring token or an authenticated admin JWT.

    This protects autonomous control-plane endpoints that may be called by an
    operator session or by trusted internal automation.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization Bearer requerido",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.split(" ", 1)[1].strip()
    monitor_token = settings.ZENTHRA_MONITOR_TOKEN
    if monitor_token and secrets.compare_digest(token, monitor_token):
        return {"auth_type": "monitor_token", "role": "internal"}

    try:
        secret = settings.SECRET_KEY
        if hasattr(secret, "get_secret_value"):
            secret = secret.get_secret_value()
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM])
        email: str | None = payload.get("sub")
        if not email:
            raise JWTError("missing subject")
    except JWTError as err:
        if monitor_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token invalido",
            ) from err
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No se pudo validar las credenciales",
            headers={"WWW-Authenticate": "Bearer"},
        ) from err

    user = UserService.get_user_by_email(db, email=email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No se pudo validar las credenciales",
            headers={"WWW-Authenticate": "Bearer"},
        )

    role = getattr(user, "role", None)
    if role not in ("admin", "administrator", "superadmin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permisos insuficientes. Requiere rol administrador.",
        )

    if hasattr(user, "is_active") and not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuario inactivo. Contacta con el administrador.",
        )

    return user

