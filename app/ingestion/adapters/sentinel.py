from __future__ import annotations

from typing import Any

from app.ingestion.adapters.common import compact_labels, first_value


def adapt_sentinel_event(payload: dict[str, Any]) -> dict[str, Any]:
    incident_id = first_value(payload, ["id", "incidentNumber", "properties.incidentNumber"], "unknown")
    title = first_value(payload, ["title", "properties.title", "AlertName"], "Sentinel incident")
    severity = first_value(payload, ["severity", "properties.severity", "AlertSeverity"], "medium")
    provider = first_value(payload, ["providerName", "properties.providerName"], "Microsoft Sentinel")
    source_ip = first_value(payload, ["sourceIp", "SourceIP", "entities.0.address"], "")
    target = first_value(
        payload,
        ["compromisedEntity", "properties.owner.assignedTo", "Computer", "Account", "HostName"],
        "sentinel-target",
    )
    description = first_value(
        payload,
        ["description", "properties.description", "ExtendedProperties.Description"],
        title,
    )

    return {
        "source": "sentinel/siem",
        "alertname": "SentinelIncident",
        "title": f"Sentinel {incident_id}: {title}",
        "description": description,
        "severity": str(severity).lower(),
        "category": "siem",
        "target": str(target),
        "source_ip": source_ip,
        "fingerprint": f"sentinel|{incident_id}|{target}|{title}",
        "event": payload,
        "labels": compact_labels(
            {
                "job": "sentinel",
                "incident_id": incident_id,
                "provider": provider,
                "source_ip": source_ip,
                "target": target,
            }
        ),
    }
