# =============================================================
# 🧩 AuthSchema — ZENTHRA.CORE_SECURITY (v2.1 JSON MODE)
# =============================================================
# Esquemas Pydantic para la autenticación de usuarios.
# Implementación moderna compatible con JWT (Bearer Tokens).
#
# Incluye:
#   - LoginRequest → credenciales de entrada
#   - TokenResponse → estructura del token devuelto
#   - TokenData → datos del token decodificado
# =============================================================

from typing import Optional

from pydantic import BaseModel, EmailStr, Field


# =============================================================
# 🧠 LoginRequest
# -------------------------------------------------------------
# Se usa en el endpoint /auth/login.
# Recibe el email (como username) y la contraseña en formato JSON.
# =============================================================
class LoginRequest(BaseModel):
    username: EmailStr = Field(..., examples=["analyst@zenthra.com"])
    password: str = Field(..., min_length=6, examples=["use-a-strong-password"])


# =============================================================
# 🔐 TokenResponse
# -------------------------------------------------------------
# Devuelto por el endpoint /auth/login tras autenticación correcta.
# Contiene el JWT generado por el backend.
# =============================================================
class TokenResponse(BaseModel):
    access_token: str = Field(..., description="JWT generado para el usuario autenticado")
    token_type: str = Field(default="bearer", description="Tipo de token (Bearer)")


# =============================================================
# 🧬 TokenData
# -------------------------------------------------------------
# Representa la información contenida en el JWT decodificado.
# Usado internamente por el servicio de seguridad (core/security).
# =============================================================
class TokenData(BaseModel):
    sub: Optional[str] = Field(None, description="Identificador del usuario (email)")
