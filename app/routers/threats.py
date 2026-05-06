# =============================================================
# 🚨 ThreatsRouter — ZENTHRA.CORE_SECURITY (v2.5 Filters+Paging SIEM)
# =============================================================
# ✅ Mejoras:
#   - Compatibilidad con paginación por page/limit (además de skip/limit)
#   - Filtros SIEM: source, active(open), fingerprint, title
#   - Orden: updated_at/created_at + asc/desc
#   - No rompe endpoints existentes
# =============================================================

import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.security import (
    get_current_admin,  # 🔐 solo admin (escritura)
    get_current_user,  # 🔓 usuario autenticado (lectura)
)
from app.db.session import get_db
from app.models.user import User  # para tipar current_user / current_admin
from app.schemas.threat_schema import ThreatCreate, ThreatResponse, ThreatUpdate
from app.services.threat_service import ThreatService

AUDIT_LOG = logging.getLogger("zenthra.threats_audit")

router = APIRouter(
    prefix="/threats",
    tags=["Threats"],
    responses={404: {"description": "No encontrado"}},
)


@router.post(
    "/",
    response_model=ThreatResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar una nueva amenaza (admin)",
)
def create_threat(
    threat_data: ThreatCreate,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
):
    service = ThreatService(db)

    threat_data.created_by = str(getattr(current_admin, "id", "")) or None
    threat = service.create_threat(threat_data)

    AUDIT_LOG.info(
        "[THREAT_CREATE] user_id=%s email=%s role=%s threat_id=%s level=%s source=%s title=%s",
        getattr(current_admin, "id", None),
        getattr(current_admin, "email", None),
        getattr(current_admin, "role", None),
        getattr(threat, "id", None),
        getattr(threat, "level", None),
        getattr(threat, "source", None),
        getattr(threat, "title", None),
    )

    return threat


# =============================================================
# 📘 LISTAR AMENAZAS (cualquier usuario autenticado)
# =============================================================
@router.get(
    "/",
    response_model=List[ThreatResponse],
    summary="Listar amenazas (con filtros SIEM)",
)
def list_threats(
    # --- Compatibilidad ---
    # Si viene page/limit → calculamos skip = (page-1)*limit
    page: Optional[int] = Query(
        None, ge=1, description="Página (opcional). Si se usa, ignora skip."
    ),
    skip: int = Query(0, ge=0, description="Número de amenazas a omitir (offset)"),
    limit: int = Query(20, ge=1, le=100, description="Máx. resultados (1..100)"),

    # --- Filtros SIEM ---
    source: Optional[str] = Query(None, description="Filtrar por source (ej: prometheus/correlation)"),
    active: Optional[bool] = Query(
        None,
        description="Si true: solo amenazas activas (siem_metadata.status=='open')",
    ),
    fingerprint: Optional[str] = Query(None, description="Filtrar por fingerprint exacto"),
    title: Optional[str] = Query(None, description="Filtrar por título (contiene)"),

    # --- Orden ---
    sort: str = Query("updated_at", pattern="^(updated_at|created_at)$", description="Campo de orden"),
    order: str = Query("desc", pattern="^(asc|desc)$", description="Dirección de orden"),

    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    📊 Lista amenazas con filtros SIEM.
    - Requiere JWT usuario activo.
    - Compatibilidad: acepta page/limit o skip/limit.
    """
    # page/limit override
    if page is not None:
        skip = (page - 1) * limit

    service = ThreatService(db)

    # Si tu ThreatService aún no soporta filtros, aquí hacemos fallback
    # implementando el filtrado en el Service en el siguiente paso si hace falta.
    return service.get_all_threats(
        skip=skip,
        limit=limit,
        source=source,
        active=active,
        fingerprint=fingerprint,
        title=title,
        sort=sort,
        order=order,
    )


@router.get(
    "/{threat_id}",
    response_model=ThreatResponse,
    summary="Obtener detalles de una amenaza por ID",
)
def get_threat(
    threat_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = ThreatService(db)
    threat = service.get_threat_by_id(threat_id)
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Amenaza no encontrada",
        )
    return threat


@router.put(
    "/{threat_id}",
    response_model=ThreatResponse,
    summary="Actualizar amenaza existente (admin)",
)
def update_threat(
    threat_id: UUID,
    update_data: ThreatUpdate,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
):
    service = ThreatService(db)
    threat = service.update_threat(threat_id, update_data)

    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Amenaza no encontrada o no actualizada",
        )

    AUDIT_LOG.info(
        "[THREAT_UPDATE] user_id=%s email=%s role=%s threat_id=%s level=%s source=%s title=%s",
        getattr(current_admin, "id", None),
        getattr(current_admin, "email", None),
        getattr(current_admin, "role", None),
        getattr(threat, "id", None),
        getattr(threat, "level", None),
        getattr(threat, "source", None),
        getattr(threat, "title", None),
    )

    return threat


@router.delete(
    "/{threat_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Eliminar amenaza del sistema (admin)",
)
def delete_threat(
    threat_id: UUID,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
):
    service = ThreatService(db)
    deleted = service.delete_threat(threat_id)

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Amenaza no encontrada",
        )

    AUDIT_LOG.info(
        "[THREAT_DELETE] user_id=%s email=%s role=%s threat_id=%s",
        getattr(current_admin, "id", None),
        getattr(current_admin, "email", None),
        getattr(current_admin, "role", None),
        threat_id,
    )

    return None