# =============================================================
# 👤 UserModel — ZENTHRA.CORE_SECURITY (v2.1 Hardened Stable)
# =============================================================
# Representa a los usuarios registrados dentro del sistema.
#
# Características:
#  - ID basado en UUID (String(36)) como clave primaria
#    → mejora seguridad y unicidad global frente a IDs incrementales.
#  - Campo `role` usado por el módulo de seguridad:
#       · "admin" / "administrator" / "superadmin" → acceso elevado
#       · "user" (por defecto) → acceso estándar
#  - Campo `is_active` usado por `get_current_active_user` para
#    bloquear accesos sin eliminar la cuenta.
#  - Relación ORM con ThreatModel (amenazas generadas por el usuario).
# =============================================================

import uuid

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class User(Base):
    """
    🧠 Modelo de base de datos para los usuarios del sistema ZENTHRA.

    Cada usuario puede estar asociado a múltiples amenazas (ThreatModel),
    creadas manualmente o generadas por el motor de correlación
    ZENTHRA.CORE_SECURITY.
    """

    __tablename__ = "users"

    # ---------------------------------------------------------
    # 🆔 Identificador único universal (UUID)
    # ---------------------------------------------------------
    # Se almacena como texto (String(36)) para mantener compatibilidad
    # con la mayoría de motores SQL y facilitar logs/depuración.
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )

    # ---------------------------------------------------------
    # 📛 Información básica del usuario
    # ---------------------------------------------------------
    full_name: Mapped[str] = mapped_column(String(255), nullable=True)

    # Rol lógico de seguridad (controlado por app.core.security):
    #   - "admin" / "administrator" / "superadmin" → acceso admin
    #   - "user" → acceso estándar (por defecto)
    role: Mapped[str] = mapped_column(String(50), default="user")

    # ---------------------------------------------------------
    # 📧 Autenticación y acceso
    # ---------------------------------------------------------
    # Email único, utilizado como identificador principal de login.
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )

    # Hash de la contraseña (nunca almacenar texto plano).
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    # ---------------------------------------------------------
    # ⚙️ Estado del usuario
    # ---------------------------------------------------------
    # Campo evaluado por:
    #   - get_current_active_user → bloquea acceso si es False.
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )

    # ---------------------------------------------------------
    # 🔗 Relación con amenazas (ThreatModel)
    # ---------------------------------------------------------
    # Permite acceder a todas las amenazas creadas por el usuario.
    threats = relationship(
        "ThreatModel",
        back_populates="user",
        lazy="selectin",
    )

    # ---------------------------------------------------------
    # 🧾 Representación legible para logs/depuración
    # ---------------------------------------------------------
    def __repr__(self) -> str:
        return (
            f"<User id={self.id} email={self.email} "
            f"role={self.role} active={self.is_active}>"
        )
