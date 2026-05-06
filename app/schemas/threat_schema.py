# =============================================================
# 📦 Threat Schemas — ZENTHRA.CORE_SECURITY
# =============================================================
# Esquemas Pydantic para:
# - Crear amenazas (ThreatCreate)
# - Actualizar amenazas (ThreatUpdate)
# - Responder amenazas al cliente (ThreatResponse)
#
# Notas de diseño:
# - ThreatResponse incluye fingerprint y siem_metadata
#   para soporte SIEM real (dedupe, lifecycle, evidence)
# - Campos opcionales para compatibilidad con datos antiguos
# =============================================================

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


# =============================================================
# 🧱 Base común
# =============================================================
class ThreatBase(BaseModel):
    """
    Campos comunes a todas las amenazas.
    """

    title: str = Field(..., description="Título descriptivo de la amenaza")
    source: Optional[str] = Field(None, description="Origen de la amenaza (manual, prometheus/correlation, etc.)")
    description: Optional[str] = Field(None, description="Descripción detallada")
    level: Optional[str] = Field(None, description="Nivel de severidad (low|medium|high|critical)")
    category: Optional[str] = Field(None, description="Categoría de la amenaza (availability, network, performance...)")
    score: Optional[int] = Field(None, description="Puntuación de riesgo (0–100)")
    target_service: Optional[str] = Field(None, description="Servicio afectado")
    source_ip: Optional[str] = Field(None, description="IP origen (si aplica)")
    database_name: Optional[str] = Field(None, description="Base de datos afectada (si aplica)")
    database_host: Optional[str] = Field(None, description="Host de la base de datos (si aplica)")


# =============================================================
# 📥 Crear amenaza (POST /threats)
# =============================================================
class ThreatCreate(ThreatBase):
    """
    Payload para crear amenazas manuales (admin).
    Las automáticas se crean desde el correlation engine.
    """

    created_by: Optional[str] = Field(None, description="ID del usuario que crea la amenaza")


# =============================================================
# ✏️ Actualizar amenaza (PUT /threats/{id})
# =============================================================
class ThreatUpdate(BaseModel):
    """
    Campos actualizables de una amenaza existente.
    """

    title: Optional[str] = None
    description: Optional[str] = None
    level: Optional[str] = None
    category: Optional[str] = None
    score: Optional[int] = None
    target_service: Optional[str] = None
    source_ip: Optional[str] = None
    database_name: Optional[str] = None
    database_host: Optional[str] = None


# =============================================================
# 📤 Respuesta al cliente (GET /threats)
# =============================================================
class ThreatResponse(ThreatBase):
    """
    Representa una amenaza devuelta al cliente.

    Incluye campos SIEM:
    - fingerprint: deduplicación / correlación
    - siem_metadata: lifecycle + evidence + occurrences
    """

    id: str = Field(..., description="ID único de la amenaza")
    created_at: datetime = Field(..., description="Fecha de creación")
    updated_at: Optional[datetime] = Field(None, description="Última actualización")
    created_by: Optional[str] = Field(None, description="Usuario que creó la amenaza")

    # 🧬 Dedupe / correlación
    fingerprint: Optional[str] = Field(
        None,
        description="Fingerprint SIEM para deduplicación y correlación",
    )

    # 🧠 Estado SIEM / evidencia (JSON flexible)
    siem_metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Metadatos SIEM (status, occurrences, evidence, timestamps)",
    )

    class Config:
        # Permite construir el schema directamente desde modelos ORM (SQLAlchemy)
        from_attributes = True

        # Ejemplo para OpenAPI / Swagger
        json_schema_extra = {
            "example": {
                "id": "d31c5d86-2a21-4b6f-b3a4-5d4f5eab15a2",
                "title": "Endpoint externo caído (EndpointDownBlackbox)",
                "source": "prometheus/correlation",
                "description": "Blackbox detecta endpoint no 2xx/no alcanzable.",
                "level": "medium",
                "category": "availability",
                "score": 70,
                "target_service": "external-endpoint",
                "fingerprint": "EndpointDownBlackbox|http://127.0.0.1:9999/health|blackbox|external-endpoints",
                "siem_metadata": {
                    "status": "open",
                    "first_seen_at": "2025-12-26T15:52:12Z",
                    "last_seen_at": "2025-12-26T16:05:44Z",
                    "occurrences": 4,
                    "evidence": {
                        "labels": {
                            "alertname": "EndpointDownBlackbox",
                            "job": "blackbox",
                        },
                        "annotations": {
                            "summary": "Endpoint externo caído",
                        },
                        "state": "firing",
                        "value": "1",
                    },
                },
                "created_at": "2025-12-26T15:52:12Z",
                "updated_at": "2025-12-26T16:05:44Z",
                "created_by": None,
            }
        }