# =============================================================
# ðŸ§  ThreatService â€” VAELQORIX.XDR_COMMAND
# =============================================================
# Servicio de dominio para gestionar amenazas (Threats).
#
# Responsabilidades:
# - Orquestar llamadas al ThreatRepository
# - Convertir modelos ORM â†’ dict â†’ Pydantic (ThreatResponse)
# - Aplicar validaciones de dominio (existencia, errores 404)
#
# NOTA:
# - La lÃ³gica de filtrado/orden/paginaciÃ³n vive en el Repository
# - Este servicio NO conoce SQLAlchemy queries directamente
# =============================================================

import logging
from typing import List, Optional
from uuid import UUID

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.repositories.threat_repository import ThreatRepository
from app.schemas.threat_schema import ThreatCreate, ThreatResponse, ThreatUpdate

LOG = logging.getLogger("vaelqorix.threats_service")


class ThreatService:
    """
    Capa de servicio para Threats.
    Encapsula la lÃ³gica de aplicaciÃ³n entre Router y Repository.
    """

    def __init__(self, db: Session):
        # Inyectamos la sesiÃ³n de DB en el repository
        self.repo = ThreatRepository(db)

    # ---------------------------------------------------------
    # ðŸŸ¢ Crear amenaza
    # ---------------------------------------------------------
    def create_threat(self, threat_data: ThreatCreate) -> ThreatResponse:
        """
        Crea una nueva amenaza en la base de datos.

        - Usado por amenazas manuales (admin)
        - Amenazas automÃ¡ticas se crean desde el correlation engine
        """
        threat = self.repo.create(threat_data)

        # Convertimos ORM â†’ dict â†’ Pydantic
        return ThreatResponse.model_validate(threat.to_dict())

    # ---------------------------------------------------------
    # ðŸ“˜ Obtener amenazas (con filtros SIEM)
    # ---------------------------------------------------------
    def get_all_threats(
        self,
        skip: int = 0,
        limit: int = 20,
        source: Optional[str] = None,
        active: Optional[bool] = None,
        fingerprint: Optional[str] = None,
        title: Optional[str] = None,
        sort: str = "updated_at",
        order: str = "desc",
    ) -> List[ThreatResponse]:
        """
        Devuelve una lista paginada de amenazas.

        Filtros soportados:
        - source: ej. "prometheus/correlation"
        - active=True: solo amenazas activas (siem_metadata.status == "open")
        - fingerprint: coincidencia exacta
        - title: bÃºsqueda parcial (case-insensitive)
        - sort: updated_at | created_at
        - order: asc | desc
        """

        # Delegamos TODA la query al repository
        threats = self.repo.get_all_filtered(
            skip=skip,
            limit=limit,
            source=source,
            active=active,
            fingerprint=fingerprint,
            title=title,
            sort=sort,
            order=order,
        )

        results: List[ThreatResponse] = []

        # SerializaciÃ³n segura: ORM â†’ dict â†’ Pydantic
        for t in threats:
            try:
                results.append(
                    ThreatResponse.model_validate(t.to_dict())
                )
            except ValidationError as e:
                # Si un registro rompe el schema, lo logueamos y seguimos
                LOG.error(
                    "âŒ ValidationError serializando Threat id=%s: %s",
                    getattr(t, "id", "unknown"),
                    e,
                )
            except Exception as e:
                # Error inesperado (no rompe la respuesta completa)
                LOG.exception(
                    "âŒ Error inesperado serializando Threat id=%s: %s",
                    getattr(t, "id", "unknown"),
                    e,
                )

        return results

    # ---------------------------------------------------------
    # ðŸ” Obtener amenaza por ID
    # ---------------------------------------------------------
    def get_threat_by_id(self, threat_id: UUID) -> ThreatResponse:
        """
        Devuelve una amenaza concreta por su ID.
        """
        threat = self.repo.get_by_id(str(threat_id))
        if not threat:
            raise HTTPException(
                status_code=404,
                detail=f"Amenaza con ID {threat_id} no encontrada.",
            )

        return ThreatResponse.model_validate(threat.to_dict())

    # ---------------------------------------------------------
    # âœï¸ Actualizar amenaza existente
    # ---------------------------------------------------------
    def update_threat(
        self,
        threat_id: UUID,
        update_data: ThreatUpdate,
    ) -> ThreatResponse:
        """
        Actualiza una amenaza existente (solo admin).
        """
        updated = self.repo.update(str(threat_id), update_data)
        if not updated:
            raise HTTPException(
                status_code=404,
                detail=f"No se pudo actualizar la amenaza {threat_id} (no existe).",
            )

        return ThreatResponse.model_validate(updated.to_dict())

    # ---------------------------------------------------------
    # âŒ Eliminar amenaza
    # ---------------------------------------------------------
    def delete_threat(self, threat_id: UUID) -> bool:
        """
        Elimina una amenaza del sistema (solo admin).
        """
        deleted = self.repo.delete(str(threat_id))
        if not deleted:
            raise HTTPException(
                status_code=404,
                detail=f"Amenaza con ID {threat_id} no encontrada para eliminar.",
            )

        return True