from __future__ import annotations

from typing import Any

from app.ingestion.adapters.common import compact_labels, first_value


def adapt_iam_event(payload: dict[str, Any]) -> dict[str, Any]:
    event_id = first_value(payload, ["event_id", "id", "request_id"], "unknown-iam-event")
    user = first_value(payload, ["user", "username", "principal", "actor.email"], "unknown-user")
    source_ip = first_value(payload, ["source_ip", "ip", "client.ip", "actor.ip"], "")
    event_name = first_value(payload, ["event_name", "action", "type"], "IAMEvent")
    severity = first_value(payload, ["severity", "risk", "risk_level"], "medium")

    return {
        "source": "iam",
        "alertname": str(event_name),
        "title": f"IAM {event_name} for {user}",
        "description": first_value(payload, ["description", "message"], f"IAM event {event_name}"),
        "severity": severity,
        "category": "iam",
        "target": user,
        "source_ip": source_ip,
        "fingerprint": f"iam|{event_name}|{user}|{source_ip}|{event_id}",
        "event": payload,
        "labels": compact_labels(
            {
                "job": "iam",
                "event_id": event_id,
                "user": user,
                "source_ip": source_ip,
            }
        ),
    }
