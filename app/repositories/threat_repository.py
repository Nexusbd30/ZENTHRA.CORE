# =============================================================
# 🧱 ThreatRepository — ZENTHRA.CORE_SECURITY (v1.2 Filters+Sort SIEM)
# =============================================================
# ✅ Añade:
#   - get_all_filtered(...): source / active / fingerprint / title
#   - sort: updated_at|created_at + order asc|desc
#   - active portable: siem_metadata.status en Python (no depende de JSON ops DB)
# =============================================================

from typing import Any, List, Optional, Union
from uuid import UUID

from sqlalchemy import asc, desc, select
from sqlalchemy.orm import Session

from app.models.threat_model import ThreatModel
from app.schemas.threat_schema import ThreatCreate, ThreatUpdate


class ThreatRepository:
    """Clase encargada de manejar las operaciones en la tabla 'threats'."""

    def __init__(self, db: Session):
        self.db = db

    # ---------------------------------------------------------
    # 🧩 Utilidad interna: normalizar IDs
    # ---------------------------------------------------------
    def _normalize_id(self, threat_id: Union[str, UUID]) -> Optional[str]:
        if isinstance(threat_id, UUID):
            return str(threat_id)
        try:
            return str(UUID(str(threat_id)))
        except (ValueError, TypeError):
            return None

    # ---------------------------------------------------------
    # 🟢 Crear una amenaza
    # ---------------------------------------------------------
    def create(self, threat_data: ThreatCreate) -> ThreatModel:
        payload = threat_data.model_dump()
        threat = ThreatModel(**payload)
        self.db.add(threat)
        self.db.commit()
        self.db.refresh(threat)
        return threat

    # ---------------------------------------------------------
    # 📘 Obtener todas las amenazas (paginadas) — legacy
    # ---------------------------------------------------------
    def get_all(self, skip: int = 0, limit: int = 20) -> List[ThreatModel]:
        query = select(ThreatModel).offset(skip).limit(limit)
        return list(self.db.scalars(query).all())

    # ---------------------------------------------------------
    # 📘 Obtener amenazas (paginadas) con filtros SIEM
    # ---------------------------------------------------------
    def get_all_filtered(
        self,
        *,
        skip: int = 0,
        limit: int = 20,
        source: Optional[str] = None,
        active: Optional[bool] = None,
        fingerprint: Optional[str] = None,
        title: Optional[str] = None,
        sort: str = "updated_at",   # updated_at|created_at
        order: str = "desc",        # asc|desc
    ) -> List[ThreatModel]:
        """
        Recupera amenazas con filtros SIEM.

        - source: "prometheus/correlation"
        - fingerprint: exact
        - title: contains (case-insensitive)
        - active=True: siem_metadata.status == "open" (portable: filtro en Python)
        - sort/order: orden por updated_at o created_at
        """

        # --- ordenar ---
        sort_col = ThreatModel.updated_at if sort == "updated_at" else ThreatModel.created_at
        order_by = desc(sort_col) if order == "desc" else asc(sort_col)

        # --- query base ---
        q = select(ThreatModel)

        if source:
            q = q.where(ThreatModel.source == source)

        if fingerprint:
            q = q.where(ThreatModel.fingerprint == fingerprint)

        if title:
            # ilike funciona en Postgres; en SQLite SQLAlchemy suele traducirlo
            q = q.where(ThreatModel.title.ilike(f"%{title}%"))

        q = q.order_by(order_by)

        # --- active: filtro portable (en Python) ---
        # Como no podemos depender de operadores JSON (SQLite/Postgres), hacemos:
        # 1) Traemos un buffer (limit*5)
        # 2) Filtramos siem_metadata.status
        # 3) Devolvemos los primeros `limit`
        if active is not None:
            fetch_limit = max(limit * 5, limit)
            rows = self.db.scalars(q.offset(skip).limit(fetch_limit)).all()

            def is_open(t: ThreatModel) -> bool:
                meta: dict[str, Any] = (
                    t.siem_metadata if isinstance(t.siem_metadata, dict) else {}
                )
                return meta.get("status") == "open"

            filtered = [t for t in rows if is_open(t)] if active else [t for t in rows if not is_open(t)]
            return filtered[:limit]

        # sin filtro active
        return list(self.db.scalars(q.offset(skip).limit(limit)).all())

    # ---------------------------------------------------------
    # 🔍 Obtener amenaza por ID
    # ---------------------------------------------------------
    def get_by_id(self, threat_id: Union[str, UUID]) -> Optional[ThreatModel]:
        uid = self._normalize_id(threat_id)
        if uid is None:
            return None
        return self.db.get(ThreatModel, uid)

    # ---------------------------------------------------------
    # ✏️ Actualizar amenaza existente
    # ---------------------------------------------------------
    def update(
        self,
        threat_id: Union[str, UUID],
        update_data: ThreatUpdate,
    ) -> Optional[ThreatModel]:
        uid = self._normalize_id(threat_id)
        if uid is None:
            return None

        threat = self.get_by_id(uid)
        if not threat:
            return None

        changes = update_data.model_dump(exclude_unset=True)
        for key, value in changes.items():
            setattr(threat, key, value)

        self.db.commit()
        self.db.refresh(threat)
        return threat

    # ---------------------------------------------------------
    # ❌ Eliminar amenaza
    # ---------------------------------------------------------
    def delete(self, threat_id: Union[str, UUID]) -> bool:
        uid = self._normalize_id(threat_id)
        if uid is None:
            return False

        threat = self.get_by_id(uid)
        if not threat:
            return False

        self.db.delete(threat)
        self.db.commit()
        return True
