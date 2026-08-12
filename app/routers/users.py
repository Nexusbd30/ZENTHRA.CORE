# ==============================================================
# ðŸ‘¥ USERS ROUTER â€” VAELQORIX.XDR_COMMAND (v3.0 Hardened)
# ==============================================================
# Endpoints clave:
#   - POST   /users/                    â†’ crear usuario  (actualmente pÃºblico)
#   - GET    /users/me                  â†’ perfil del usuario autenticado
#   - GET    /users/                    â†’ listar usuarios (SOLO ADMIN)
#   - GET    /users/{user_id}           â†’ obtener usuario por ID (SOLO ADMIN)
#   - POST   /users/reset-password      â†’ resetear contraseÃ±a (actualmente pÃºblico)
#   - PUT    /users/{user_id}           â†’ actualizar usuario (SOLO ADMIN)
#   - DELETE /users/{user_id}           â†’ eliminar usuario (SOLO ADMIN)
#
# Notas de seguridad:
#   - El control de JWT se hace con las dependencias:
#       Â· get_current_user
#       Â· get_current_active_user
#       Â· get_current_admin
#   - No se ha roto ningÃºn contrato de respuesta ni nombres de ruta.
# ==============================================================

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.security import (
    get_current_active_user,
    get_current_admin,
)
from app.db.session import get_db
from app.models.user import User
from app.schemas.user_schema import (
    ResetPasswordRequest,
    UserCreate,
    UserOutPaginated,
    UserRead,
    UserUpdate,
)
from app.services.runtime_log_service import list_runtime_logs
from app.services.user_service import UserService

# ==============================================================
# ðŸ“Œ ROUTER PRINCIPAL â€” USERS
# ==============================================================
router = APIRouter(
    prefix="/users",
    tags=["users"],
)


# ==============================================================
# ðŸŸ¢ CREAR USUARIO  (registro)
# ==============================================================
@router.post("/", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    user: UserCreate,
    db: Session = Depends(get_db),
    # âš ï¸ Seguridad:
    # En entorno Enterprise/ProducciÃ³n, normalmente se restringe a admin:
    # current_admin: User = Depends(get_current_admin),
):
    """
    Crear un nuevo usuario.

    - Valida que el email no exista.
    - Cifra la contraseÃ±a antes de guardar (UserService).
    - Actualmente NO requiere autenticaciÃ³n, para permitir registro
      desde la pantalla de /register (frontend).

    ðŸ’¡ Si quieres modo totalmente cerrado (solo admin crea cuentas),
       descomenta la dependencia get_current_admin y elimina el comentario.
    """
    db_user = UserService.get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El email ya estÃ¡ registrado",
        )
    return UserService.create_user(db, user)


# ==============================================================
# ðŸ”’ PERFIL DEL USUARIO ACTUAL
# ==============================================================
@router.get("/me", response_model=UserRead)
def read_user_me(
    current_user: User = Depends(get_current_active_user),
):
    """
    Devuelve la informaciÃ³n del usuario autenticado (JWT).

    Requisitos:
      - Token JWT vÃ¡lido.
      - Usuario con is_active = True (gestionado por get_current_active_user).

    Si el usuario estÃ¡ desactivado, se devuelve 403 automÃ¡ticamente
    desde el helper de seguridad.
    """
    return current_user


@router.get("/runtime-logs")
def get_runtime_logs_for_user(
    limit: int = Query(200, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    current_user: User = Depends(get_current_active_user),
):
    """
    Devuelve logs reales del backend para el dashboard autenticado.

    Se protege con JWT de usuario para no depender del monitor token
    en pantallas normales del frontend.
    """
    _ = current_user
    return list_runtime_logs(limit=limit, severity=severity, search=search)


# ==============================================================
# ðŸ“„ OBTENER USUARIOS (PaginaciÃ³n + Filtros + BÃºsqueda) â€” SOLO ADMIN
# ==============================================================
@router.get("/", response_model=UserOutPaginated)
def list_users(
    page: int = Query(1, ge=1, description="NÃºmero de pÃ¡gina"),
    limit: int = Query(10, ge=1, le=100, description="Cantidad por pÃ¡gina"),
    role: Optional[str] = Query(
        None, description="Filtrar por rol (admin/user)"
    ),
    is_active: Optional[bool] = Query(
        None, description="Filtrar por estado (activo/inactivo)"
    ),
    search: Optional[str] = Query(
        None, description="Buscar por nombre o email"
    ),
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
):
    """
    Devuelve una lista paginada de usuarios con filtros opcionales.

    ðŸ”’ Requisitos de seguridad:
      - Token JWT vÃ¡lido.
      - Usuario con rol de administrador (get_current_admin).

    El frontend ya llama con:
      GET /users/?page=1&limit=20
    y ahora este endpoint solo serÃ¡ accesible por perfiles admin.
    """
    return UserService.get_users_paginated(
        db=db,
        page=page,
        limit=limit,
        role=role,
        is_active=is_active,
        search=search,
    )


# ==============================================================
# ðŸ” OBTENER USUARIO POR ID â€” SOLO ADMIN
# ==============================================================
@router.get("/{user_id}", response_model=UserRead)
def read_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
):
    """
    Obtiene un usuario por su ID (UUID).

    ðŸ”’ Requisitos:
      - Solo accesible por admin.
      - El resto de usuarios deben usar `/users/me` para consultar
        su propio perfil.
    """
    user = UserService.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado",
        )
    return user


@router.patch("/{user_id}/toggle-active", response_model=UserRead)
def toggle_user_active(
    user_id: str,
    is_active: bool = Query(..., description="Nuevo estado activo/inactivo"),
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
):
    _ = current_admin
    user = UserService.set_user_active(db, user_id, is_active)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado",
        )
    return user


# ==============================================================
# ðŸ”‘ RESETEAR CONTRASEÃ‘A  (por email)
# ==============================================================
@router.post("/reset-password", response_model=UserRead)
def reset_password(
    request: ResetPasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Permite cambiar la contraseÃ±a de un usuario existente.

    - Busca el usuario por email.
    - Reescribe su hash de contraseÃ±a.
    - Solo puede usarlo el propio usuario autenticado o un admin.

    âš ï¸ AVISO DE SEGURIDAD:
      Este endpoint ya no es pÃºblico. Para recuperaciÃ³n sin sesiÃ³n
      debe implementarse un flujo dedicado con token temporal.
    """
    current_email = (getattr(current_user, "email", "") or "").strip().lower()
    requested_email = str(request.email).strip().lower()
    current_role = (getattr(current_user, "role", "") or "").strip().lower()

    if current_role not in {"admin", "administrator", "superadmin"} and current_email != requested_email:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Solo puedes cambiar tu propia contraseÃ±a.",
        )

    user = UserService.reset_password(
        db,
        request.email,
        request.new_password,
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado",
        )
    return user


# ==============================================================
# âœï¸ ACTUALIZAR USUARIO â€” SOLO ADMIN
# ==============================================================
@router.put("/{user_id}", response_model=UserRead)
def update_user(
    user_id: str,
    user_update: UserUpdate,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
):
    """
    Actualiza los datos de un usuario.

    - Permite cambiar email, nombre, rol, estado, etc.
    - LÃ³gica de actualizaciÃ³n delegada en UserService.

    ðŸ”’ Requisitos:
      - Token JWT vÃ¡lido.
      - Rol admin (gestiona altas/bajas/cambios).
    """
    updated_user = UserService.update_user(db, user_id, user_update)
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado o no actualizado",
        )
    return updated_user


# ==============================================================
# ðŸ—‘ï¸ ELIMINAR USUARIO â€” SOLO ADMIN
# ==============================================================
@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
):
    """
    Elimina un usuario por su ID.

    ðŸ”’ Requisitos:
      - Token JWT vÃ¡lido.
      - Rol admin.

    Si el usuario no existe, devuelve 404.
    """
    deleted = UserService.delete_user(db, user_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado",
        )
    # FastAPI devolverÃ¡ 204 No Content al no devolver cuerpo.
    return None
