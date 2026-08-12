# =============================================================
# ðŸ§© AuthSchema â€” VAELQORIX.XDR_COMMAND (v2.1 JSON MODE)
# =============================================================
# Esquemas Pydantic para la autenticaciÃ³n de usuarios.
# ImplementaciÃ³n moderna compatible con JWT (Bearer Tokens).
#
# Incluye:
#   - LoginRequest â†’ credenciales de entrada
#   - TokenResponse â†’ estructura del token devuelto
#   - TokenData â†’ datos del token decodificado
# =============================================================

from typing import Optional

from pydantic import BaseModel, EmailStr, Field


# =============================================================
# ðŸ§  LoginRequest
# -------------------------------------------------------------
# Se usa en el endpoint /auth/login.
# Recibe el email (como username) y la contraseÃ±a en formato JSON.
# =============================================================
class LoginRequest(BaseModel):
    username: EmailStr = Field(..., examples=["analyst@vaelqorix.com"])
    password: str = Field(..., min_length=6, examples=["use-a-strong-password"])


# =============================================================
# ðŸ” TokenResponse
# -------------------------------------------------------------
# Devuelto por el endpoint /auth/login tras autenticaciÃ³n correcta.
# Contiene el JWT generado por el backend.
# =============================================================
class TokenResponse(BaseModel):
    access_token: str = Field(..., description="JWT generado para el usuario autenticado")
    token_type: str = Field(default="bearer", description="Tipo de token (Bearer)")


# =============================================================
# ðŸ§¬ TokenData
# -------------------------------------------------------------
# Representa la informaciÃ³n contenida en el JWT decodificado.
# Usado internamente por el servicio de seguridad (core/security).
# =============================================================
class TokenData(BaseModel):
    sub: Optional[str] = Field(None, description="Identificador del usuario (email)")
