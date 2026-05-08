from __future__ import annotations

from typing import Any

from app.ingestion.adapters.common import compact_labels, first_value


def adapt_edr_event(payload: dict[str, Any]) -> dict[str, Any]:
    detection_id = first_value(payload, ["detection_id", "id", "alert.id"], "unknown-detection")
    host = first_value(payload, ["host", "hostname", "device.name", "endpoint.name"], "unknown-endpoint")
    severity = first_value(payload, ["severity", "alert.severity"], "medium")
    tactic = first_value(payload, ["mitre.tactic", "tactic", "category"], "endpoint")
    source_ip = first_value(payload, ["source_ip", "network.source_ip"], "")

    return {
        "source": "edr",
        "alertname": first_value(payload, ["name", "alert.name"], "EndpointDetection"),
        "title": f"EDR detection on {host}",
        "description": first_value(payload, ["description", "summary", "process.command_line"], "EDR detection"),
        "severity": severity,
        "category": "edr",
        "target": host,
        "source_ip": source_ip,
        "fingerprint": f"edr|{detection_id}|{host}",
        "event": payload,
        "labels": compact_labels(
            {
                "job": "edr",
                "detection_id": detection_id,
                "host": host,
                "tactic": tactic,
            }
        ),
    }
