# =============================================================
# ðŸš¨ ThreatModel â€” VAELQORIX.XDR_COMMAND (v3.3 SIEM Stable)
# =============================================================
# âœ… Incluye:
#   - fingerprint: dedupe fuerte (alertname|instance|job|service)
#   - siem_metadata: evidencia SIEM (labels/annotations/activeAt/value/state)
#
# ðŸŽ¯ FIX BACKEND DOWN (Postgres):
#   - Tu DB (Alembic) creÃ³ threats.id como String(36)
#   - AquÃ­ estaba como UUID(as_uuid=True) y Postgres fallaba con:
#       operator does not exist: character varying = uuid
#   - SoluciÃ³n: unificar ORM con DB usando String(36) + uuid4 string
# =============================================================

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.types import JSON  # âœ… JSON portable (SQLite/Postgres)

from app.models.base import Base


# =============================================================
# âš™ï¸ Enumeraciones
# =============================================================
class ThreatLevel(enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class ThreatCategory(enum.Enum):
    performance = "performance"
    availability = "availability"
    network = "network"
    database = "database"
    auth = "auth"
    other = "other"


# =============================================================
# ðŸ§© MODELO PRINCIPAL
# =============================================================
class ThreatModel(Base):
    __tablename__ = "threats"

    # ---------------------------------------------------------
    # ðŸ†” Identificador (UUID en formato STRING)
    # ---------------------------------------------------------
    # âœ… IMPORTANTE:
    # - Alembic creÃ³ esta columna como String(36)
    # - Por eso aquÃ­ NO usamos UUID nativo de Postgres
    # - Generamos UUID4 como string (igual que User.id)
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )

    # ---------------------------------------------------------
    # ðŸ“‹ InformaciÃ³n base
    # ---------------------------------------------------------
    title = Column(String(255), nullable=False)
    source = Column(String(255), nullable=False)  # prometheus/correlation, manual, firewallâ€¦
    description = Column(Text, nullable=True)

    # ---------------------------------------------------------
    # ðŸ§¬ SIEM â€” DEDUPE + EVIDENCIA
    # ---------------------------------------------------------
    fingerprint = Column(String(512), nullable=True, index=True)
    siem_metadata = Column(JSON, nullable=True)

    # ---------------------------------------------------------
    # ðŸ§­ ClasificaciÃ³n
    # ---------------------------------------------------------
    category = Column(Enum(ThreatCategory), nullable=True)  # type: ignore[var-annotated]
    score = Column(Integer, nullable=True)

    target_service = Column(String(255), nullable=True)
    source_ip = Column(String(64), nullable=True)

    database_name = Column(String(255), nullable=True)
    database_host = Column(String(255), nullable=True)

    # ---------------------------------------------------------
    # âš ï¸ Severidad
    # ---------------------------------------------------------
    level = Column(
        Enum(ThreatLevel), nullable=False, default=ThreatLevel.medium
    )  # type: ignore[var-annotated]

    # ---------------------------------------------------------
    # ðŸ•’ Timestamps
    # ---------------------------------------------------------
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # ---------------------------------------------------------
    # ðŸ‘¤ Usuario creador
    # ---------------------------------------------------------
    # âœ… TambiÃ©n coincide con Alembic: String(36) -> FK users.id
    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)

    # ---------------------------------------------------------
    # ðŸ” Helpers
    # ---------------------------------------------------------
    def __repr__(self) -> str:
        cat = self.category.value if self.category else None
        lvl = self.level.value if self.level else None
        return f"<Threat(id={self.id}, title={self.title}, level={lvl}, category={cat})>"

    def to_dict(self) -> dict:
        """SerializaciÃ³n limpia para API / frontend / exports."""
        return {
            "id": str(self.id),
            "title": self.title,
            "source": self.source,
            "description": self.description,
            "level": self.level.value if self.level else None,
            "category": self.category.value if self.category else None,
            "score": self.score,
            "target_service": self.target_service,
            "source_ip": self.source_ip,
            "database_name": self.database_name,
            "database_host": self.database_host,
            "fingerprint": self.fingerprint,
            "siem_metadata": self.siem_metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "created_by": str(self.created_by) if self.created_by else None,
        }


# =============================================================
# ðŸ”— RelaciÃ³n con User (import diferido)
# =============================================================

ThreatModel.user = relationship("User", back_populates="threats", lazy="joined")
