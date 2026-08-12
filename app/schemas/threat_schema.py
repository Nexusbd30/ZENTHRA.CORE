# =============================================================
# ðŸ“¦ Threat Schemas â€” VAELQORIX.XDR_COMMAND
# =============================================================
# Esquemas Pydantic para:
# - Crear amenazas (ThreatCreate)
# - Actualizar amenazas (ThreatUpdate)
# - Responder amenazas al cliente (ThreatResponse)
#
# Notas de diseÃ±o:
# - ThreatResponse incluye fingerprint y siem_metadata
#   para soporte SIEM real (dedupe, lifecycle, evidence)
# - Campos opcionales para compatibilidad con datos antiguos
# =============================================================

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


# =============================================================
# ðŸ§± Base comÃºn
# =============================================================
class ThreatBase(BaseModel):
    """
    Campos comunes a todas las amenazas.
    """

    title: str = Field(..., description="TÃ­tulo descriptivo de la amenaza")
    source: Optional[str] = Field(None, description="Origen de la amenaza (manual, prometheus/correlation, etc.)")
    description: Optional[str] = Field(None, description="DescripciÃ³n detallada")
    level: Optional[str] = Field(None, description="Nivel de severidad (low|medium|high|critical)")
    category: Optional[str] = Field(None, description="CategorÃ­a de la amenaza (availability, network, performance...)")
    score: Optional[int] = Field(None, description="PuntuaciÃ³n de riesgo (0â€“100)")
    target_service: Optional[str] = Field(None, description="Servicio afectado")
    source_ip: Optional[str] = Field(None, description="IP origen (si aplica)")
    database_name: Optional[str] = Field(None, description="Base de datos afectada (si aplica)")
    database_host: Optional[str] = Field(None, description="Host de la base de datos (si aplica)")


# =============================================================
# ðŸ“¥ Crear amenaza (POST /threats)
# =============================================================
class ThreatCreate(ThreatBase):
    """
    Payload para crear amenazas manuales (admin).
    Las automÃ¡ticas se crean desde el correlation engine.
    """

    created_by: Optional[str] = Field(None, description="ID del usuario que crea la amenaza")


# =============================================================
# âœï¸ Actualizar amenaza (PUT /threats/{id})
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
# ðŸ“¤ Respuesta al cliente (GET /threats)
# =============================================================
class ThreatResponse(ThreatBase):
    """
    Representa una amenaza devuelta al cliente.

    Incluye campos SIEM:
    - fingerprint: deduplicaciÃ³n / correlaciÃ³n
    - siem_metadata: lifecycle + evidence + occurrences
    """

    id: str = Field(..., description="ID Ãºnico de la amenaza")
    created_at: datetime = Field(..., description="Fecha de creaciÃ³n")
    updated_at: Optional[datetime] = Field(None, description="Ãšltima actualizaciÃ³n")
    created_by: Optional[str] = Field(None, description="Usuario que creÃ³ la amenaza")

    # ðŸ§¬ Dedupe / correlaciÃ³n
    fingerprint: Optional[str] = Field(
        None,
        description="Fingerprint SIEM para deduplicaciÃ³n y correlaciÃ³n",
    )

    # ðŸ§  Estado SIEM / evidencia (JSON flexible)
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
                "title": "Endpoint externo caÃ­do (EndpointDownBlackbox)",
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
                            "summary": "Endpoint externo caÃ­do",
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