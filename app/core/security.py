# =============================================================
# [AI] VAELQORIX.XDR_COMMAND - Security Module (v2.8 RBAC Hardened)
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

import jwt
from fastapi import Depends, Header, HTTPException, status
from jwt import InvalidTokenError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.enterprise_security import has_capability
from app.core.secrets import get_secret
from app.core.settings import settings
from app.db.session import get_db
from app.services.user_service import UserService

# =============================================================
# [CFG] CONFIGURACIÓN DEL TOKEN
# =============================================================

ALGORITHM = "HS256"


def _configured_secret(name: str, default: object) -> str:
    if hasattr(default, "get_secret_value"):
        default = default.get_secret_value()
    value = get_secret(name, str(default) if default is not None else None)
    return str(value or "")


# =============================================================
# [SEC] CONTEXTO DE HASH DE CONTRASEÑAS
# =============================================================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica que una contraseña en texto plano coincide con el hash guardado."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Genera un hash seguro para almacenar en la base de datos."""
    return pwd_context.hash(password)


# =============================================================
# [SEC] CREACIÓN DEL TOKEN JWT
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

    secret = _configured_secret("SECRET_KEY", settings.SECRET_KEY)

    return jwt.encode(to_encode, secret, algorithm=ALGORITHM)


# =============================================================
#  EXTRACCIÓN DEL TOKEN DESDE EL HEADER
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
#  OBTENER USUARIO AUTENTICADO (BÁSICO)
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
        secret = _configured_secret("SECRET_KEY", settings.SECRET_KEY)

        payload = jwt.decode(token, secret, algorithms=[ALGORITHM])
        email: str | None = payload.get("sub")
        if email is None:
            raise credentials_exception
    except InvalidTokenError as err:
        raise credentials_exception from err

    user = UserService.get_user_by_email(db, email=email)
    if user is None:
        raise credentials_exception

    return user


# =============================================================
# [OK] USUARIO ACTIVO OBLIGATORIO
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
#  USUARIO ADMIN (COMPATIBILIDAD)
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
# [SEC] RBAC FLEXIBLE (NUEVO - PRODUCCIÓN)
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
    monitor_token = get_secret("VAELQORIX_MONITOR_TOKEN", settings.VAELQORIX_MONITOR_TOKEN)
    if monitor_token and secrets.compare_digest(token, monitor_token):
        return {"auth_type": "monitor_token", "role": "internal"}

    try:
        secret = _configured_secret("SECRET_KEY", settings.SECRET_KEY)
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM])
        email: str | None = payload.get("sub")
        if not email:
            raise InvalidTokenError("missing subject")
    except InvalidTokenError as err:
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


def require_control_identity(
    authorization: str = Header(None),
    db: Session = Depends(get_db),
):
    token = get_bearer_token(authorization)
    control_token = get_secret("VAELQORIX_CONTROL_TOKEN", settings.VAELQORIX_CONTROL_TOKEN)
    monitor_token = get_secret("VAELQORIX_MONITOR_TOKEN", settings.VAELQORIX_MONITOR_TOKEN)
    if monitor_token and secrets.compare_digest(token, monitor_token):
        raise HTTPException(status_code=403, detail="Monitoring credentials cannot control actions")
    if control_token and secrets.compare_digest(token, control_token):
        return {"auth_type": "control_token", "role": "service", "tenant_id": settings.CONTROL_TOKEN_TENANT_ID or settings.DEFAULT_TENANT_ID,
                "capabilities": settings.CONTROL_TOKEN_CAPABILITIES.split(",")}
    return get_current_active_user(get_current_user(token, db))


def require_admin_or_control_token(auth_context=Depends(require_control_identity)):
    if isinstance(auth_context, dict):
        if "security:admin" not in auth_context.get("capabilities", []):
            raise HTTPException(status_code=403, detail="Control credential lacks security:admin")
        return auth_context
    return get_current_admin(auth_context)


def require_enterprise_capability(capability: str):
    def capability_checker(
        auth_context=Depends(require_control_identity),
        x_tenant_id: str | None = Header(default=None),
        x_request_id: str | None = Header(default=None),
    ):
        if str(settings.ENTERPRISE_TENANT_MODE or "").strip().lower() == "strict" and not x_tenant_id:
            raise HTTPException(status_code=400, detail="X-Tenant-ID requerido en modo multi-tenant estricto")
        if isinstance(auth_context, dict):
            tenant = auth_context.get("tenant_id", settings.DEFAULT_TENANT_ID)
            allowed = capability in auth_context.get("capabilities", [])
            actor = str(auth_context.get("auth_type", "service"))
            role = "service"
        else:
            tenant = getattr(auth_context, "tenant_id", None) or settings.DEFAULT_TENANT_ID
            role = getattr(auth_context, "role", "user")
            allowed = has_capability(role, capability)
            actor = getattr(auth_context, "email", "user")
        if x_tenant_id and x_tenant_id != tenant:
            raise HTTPException(status_code=403, detail="Tenant membership mismatch")
        if not allowed:
            raise HTTPException(status_code=403, detail=f"Capability requerida: {capability}")
        return {"actor": actor, "role": role, "tenant_id": tenant,
                "capability": capability, "request_id": x_request_id or "n/a"}
    return capability_checker
