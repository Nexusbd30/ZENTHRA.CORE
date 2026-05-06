from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

# ==========================================================
# 🧠 SCHEMAS DE ENTRADA (REQUEST)
# ==========================================================

class UserCreate(BaseModel):
    """
    Esquema para registrar un nuevo usuario.
    - Requiere email válido.
    - Requiere contraseña (mínimo 6 caracteres).
    - El nombre completo es opcional para permitir
      compatibilidad con pruebas o registros automáticos.
    """
    email: EmailStr = Field(..., description="Correo electrónico único del usuario.")
    full_name: Optional[str] = Field(None, description="Nombre completo del usuario (opcional).")
    password: str = Field(..., min_length=6, description="Contraseña del usuario.")
    role: str = Field(default="user", description="Rol del usuario (admin o user).")
    is_active: bool = Field(default=True, description="Indica si el usuario está activo.")


class ResetPasswordRequest(BaseModel):
    """
    Esquema para resetear la contraseña de un usuario.
    """
    email: EmailStr = Field(..., description="Correo del usuario que solicita el reseteo.")
    new_password: str = Field(..., min_length=6, description="Nueva contraseña en texto plano.")


class UserUpdate(BaseModel):
    """
    Esquema para actualización parcial de un usuario.
    Todos los campos son opcionales.
    """
    email: Optional[EmailStr] = Field(None, description="Nuevo email del usuario.")
    full_name: Optional[str] = Field(None, description="Nuevo nombre del usuario.")
    password: Optional[str] = Field(None, min_length=6, description="Nueva contraseña.")
    role: Optional[str] = Field(None, description="Rol del usuario (admin/user).")
    is_active: Optional[bool] = Field(None, description="Estado activo/inactivo del usuario.")


# ==========================================================
# 📤 SCHEMAS DE SALIDA (RESPONSE)
# ==========================================================

class UserRead(BaseModel):
    """
    Esquema de salida al cliente.
    Nunca incluye la contraseña.
    """
    id: UUID
    email: EmailStr
    full_name: Optional[str]
    role: str
    is_active: bool

    class Config:
        from_attributes = True  # ✅ Mapea automáticamente desde SQLAlchemy


# ==========================================================
# 📑 SCHEMA DE RESPUESTA PAGINADA — PARA /users/
# ==========================================================

class UserOutPaginated(BaseModel):
    """
    Respuesta paginada estándar:
    - items: lista de usuarios
    - total: cantidad total de registros
    - page: número de página actual
    - pages: cantidad total de páginas
    """
    items: List[UserRead]
    total: int
    page: int
    pages: int