from __future__ import annotations

from typing import Any

from app.ingestion.adapters.common import compact_labels, first_value


def adapt_qradar_event(payload: dict[str, Any]) -> dict[str, Any]:
    offense_id = first_value(payload, ["id", "offense_id"], "unknown-offense")
    description = first_value(payload, ["description", "event_description"], "QRadar offense")
    source_ip = first_value(payload, ["source_address", "source_ip", "source.ip"], "")
    target = first_value(
        payload,
        ["destination_address", "destination_ip", "destination.ip", "domain_id", "assigned_to"],
        "qradar-target",
    )
    severity = first_value(payload, ["severity", "magnitude"], "medium")

    return {
        "source": "qradar/siem",
        "alertname": "QRadarOffense",
        "title": f"QRadar offense {offense_id}",
        "description": description,
        "severity": _severity_from_qradar(severity),
        "category": first_value(payload, ["category", "offense_type"], "siem"),
        "target": str(target),
        "source_ip": source_ip,
        "fingerprint": f"qradar|{offense_id}|{target}",
        "event": payload,
        "labels": compact_labels(
            {
                "job": "qradar",
                "offense_id": offense_id,
                "source_ip": source_ip,
                "target": target,
            }
        ),
    }


def _severity_from_qradar(value: Any) -> str:
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        return str(value or "medium").lower()
    if numeric >= 8:
        return "critical"
    if numeric >= 6:
        return "high"
    if numeric >= 3:
        return "medium"
    return "low"
