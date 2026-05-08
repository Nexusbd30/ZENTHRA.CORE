from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.redqueen.ueba import analyze_ueba_signals


def _enum_value(value: Any) -> str | None:
    if value is None:
        return None
    return str(getattr(value, "value", value))


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value) if value else None


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def build_threat_perception(threat: Any) -> dict[str, Any]:
    metadata: dict[str, Any] = _dict(getattr(threat, "siem_metadata", None))
    evidence: dict[str, Any] = _dict(metadata.get("evidence"))
    labels: dict[str, Any] = _dict(evidence.get("labels"))
    annotations: dict[str, Any] = _dict(evidence.get("annotations"))
    starts_at = metadata.get("first_seen_at") or evidence.get("activeAt") or evidence.get("startsAt")
    last_seen_at = metadata.get("last_seen_at") or evidence.get("last_seen_at")
    first_seen = _parse_datetime(starts_at)
    last_seen = _parse_datetime(last_seen_at) or _parse_datetime(getattr(threat, "updated_at", None))
    active_minutes = None
    if first_seen and last_seen:
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=UTC)
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=UTC)
        active_minutes = max(0, int((last_seen - first_seen).total_seconds() // 60))

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
    if labels.get("severity"):
        factors.append(f"siem_severity:{labels['severity']}")
    if annotations.get("summary"):
        factors.append("annotation_summary_present")
    if active_minutes and active_minutes >= 15:
        factors.append(f"active_minutes:{active_minutes}")
    if getattr(threat, "source_ip", None):
        factors.append("source_ip_present")
    if getattr(threat, "database_name", None) or getattr(threat, "database_host", None):
        factors.append("database_asset")

    perception_factors = list(dict.fromkeys(str(f) for f in factors if f))
    perception = {
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
        "siem": {
            "alertname": labels.get("alertname"),
            "job": labels.get("job"),
            "instance": labels.get("instance"),
            "severity": labels.get("severity"),
            "state": evidence.get("state"),
            "value": evidence.get("value"),
            "status": metadata.get("status"),
            "occurrences": metadata.get("occurrences"),
            "first_seen_at": starts_at,
            "last_seen_at": last_seen_at,
            "active_minutes": active_minutes,
            "summary": annotations.get("summary"),
            "description": annotations.get("description"),
        },
        "created_at": _iso(getattr(threat, "created_at", None)),
        "updated_at": _iso(getattr(threat, "updated_at", None)),
        "factors": perception_factors,
    }
    ueba = analyze_ueba_signals(perception)
    perception["ueba"] = ueba
    ueba_signals = [str(item) for item in ueba.get("signals", []) if item]
    perception["factors"] = list(dict.fromkeys([*perception_factors, *ueba_signals]))
    return perception
