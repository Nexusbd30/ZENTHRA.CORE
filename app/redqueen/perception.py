from __future__ import annotations

from datetime import datetime
from typing import Any


def _enum_value(value: Any) -> str | None:
    if value is None:
        return None
    return str(getattr(value, "value", value))


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value) if value else None


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def build_threat_perception(threat: Any) -> dict[str, Any]:
    metadata: dict[str, Any] = _dict(getattr(threat, "siem_metadata", None))
    evidence: dict[str, Any] = _dict(metadata.get("evidence"))
    labels: dict[str, Any] = _dict(evidence.get("labels"))
    annotations: dict[str, Any] = _dict(evidence.get("annotations"))

    target = (
        getattr(threat, "target_service", None)
        or getattr(threat, "database_host", None)
        or labels.get("instance")
        or labels.get("service")
        or labels.get("job")
        or getattr(threat, "source_ip", None)
        or getattr(threat, "title", "unknown")
    )

    factors = [
        f"severity:{_enum_value(getattr(threat, 'level', None)) or 'unknown'}",
        f"category:{_enum_value(getattr(threat, 'category', None)) or 'unknown'}",
        f"source:{getattr(threat, 'source', None) or 'unknown'}",
    ]

    if metadata.get("status"):
        factors.append(f"status:{metadata['status']}")
    if metadata.get("occurrences"):
        factors.append(f"occurrences:{metadata['occurrences']}")
    if labels.get("alertname"):
        factors.append(f"alert:{labels['alertname']}")
    if labels.get("job"):
        factors.append(f"job:{labels['job']}")
    if getattr(threat, "source_ip", None):
        factors.append("source_ip_present")
    if getattr(threat, "database_name", None) or getattr(threat, "database_host", None):
        factors.append("database_asset")

    return {
        "threat_id": str(threat.id),
        "target": str(target),
        "title": getattr(threat, "title", None),
        "description": getattr(threat, "description", None),
        "source": getattr(threat, "source", None),
        "level": _enum_value(getattr(threat, "level", None)),
        "category": _enum_value(getattr(threat, "category", None)),
        "score": getattr(threat, "score", None),
        "fingerprint": getattr(threat, "fingerprint", None),
        "target_service": getattr(threat, "target_service", None),
        "source_ip": getattr(threat, "source_ip", None),
        "database_name": getattr(threat, "database_name", None),
        "database_host": getattr(threat, "database_host", None),
        "metadata": metadata,
        "labels": labels,
        "annotations": annotations,
        "created_at": _iso(getattr(threat, "created_at", None)),
        "updated_at": _iso(getattr(threat, "updated_at", None)),
        "factors": list(dict.fromkeys(str(f) for f in factors if f)),
    }
