# =============================================================
# ðŸ‘¤ UserModel â€” VAELQORIX.XDR_COMMAND (v2.1 Hardened Stable)
# =============================================================
# Representa a los usuarios registrados dentro del sistema.
#
# CaracterÃ­sticas:
#  - ID basado en UUID (String(36)) como clave primaria
#    â†’ mejora seguridad y unicidad global frente a IDs incrementales.
#  - Campo `role` usado por el mÃ³dulo de seguridad:
#       Â· "admin" / "administrator" / "superadmin" â†’ acceso elevado
#       Â· "user" (por defecto) â†’ acceso estÃ¡ndar
#  - Campo `is_active` usado por `get_current_active_user` para
#    bloquear accesos sin eliminar la cuenta.
#  - RelaciÃ³n ORM con ThreatModel (amenazas generadas por el usuario).
# =============================================================

import uuid

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class User(Base):
    """
    ðŸ§  Modelo de base de datos para los usuarios del sistema VAELQORIX.

    Cada usuario puede estar asociado a mÃºltiples amenazas (ThreatModel),
    creadas manualmente o generadas por el motor de correlaciÃ³n
    VAELQORIX.XDR_COMMAND.
    """

    __tablename__ = "users"

    # ---------------------------------------------------------
    # ðŸ†” Identificador Ãºnico universal (UUID)
    # ---------------------------------------------------------
    # Se almacena como texto (String(36)) para mantener compatibilidad
    # con la mayorÃ­a de motores SQL y facilitar logs/depuraciÃ³n.
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )

    # ---------------------------------------------------------
    # ðŸ“› InformaciÃ³n bÃ¡sica del usuario
    # ---------------------------------------------------------
    full_name: Mapped[str] = mapped_column(String(255), nullable=True)

    # Rol lÃ³gico de seguridad (controlado por app.core.security):
    #   - "admin" / "administrator" / "superadmin" â†’ acceso admin
    #   - "user" â†’ acceso estÃ¡ndar (por defecto)
    role: Mapped[str] = mapped_column(String(50), default="user")

    # ---------------------------------------------------------
    # ðŸ“§ AutenticaciÃ³n y acceso
    # ---------------------------------------------------------
    # Email Ãºnico, utilizado como identificador principal de login.
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )

    # Hash de la contraseÃ±a (nunca almacenar texto plano).
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    # ---------------------------------------------------------
    # âš™ï¸ Estado del usuario
    # ---------------------------------------------------------
    # Campo evaluado por:
    #   - get_current_active_user â†’ bloquea acceso si es False.
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )

    # ---------------------------------------------------------
    # ðŸ”— RelaciÃ³n con amenazas (ThreatModel)
    # ---------------------------------------------------------
    # Permite acceder a todas las amenazas creadas por el usuario.
    threats = relationship(
        "ThreatModel",
        back_populates="user",
        lazy="selectin",
    )

    # ---------------------------------------------------------
    # ðŸ§¾ RepresentaciÃ³n legible para logs/depuraciÃ³n
    # ---------------------------------------------------------
    def __repr__(self) -> str:
        return (
            f"<User id={self.id} email={self.email} "
            f"role={self.role} active={self.is_active}>"
        )
