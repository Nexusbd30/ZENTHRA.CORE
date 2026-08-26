from __future__ import annotations

from typing import Any

from app.sensors.contracts import SensorFinding, severity_from_signals

HIGH_RISK_EVENTS = {
    "iam.createaccesskey": "T1098",
    "iam.attachadminpolicy": "T1098",
    "securitygroup.authorizeingress": "T1562",
    "keyvault.secretread": "T1552",
    "storage.publicaccessenabled": "T1530",
}


def collect_cloud_findings(payload: dict[str, Any]) -> list[SensorFinding]:
    event_name = str(payload.get("event_name") or payload.get("operation") or "").lower()
    actor = str(payload.get("actor") or payload.get("principal") or "cloud:unknown")
    resource = str(payload.get("resource") or payload.get("target") or actor)
    signals: list[str] = []
    mitre: list[str] = []
    for marker, technique in HIGH_RISK_EVENTS.items():
        if marker in event_name:
            signals.append("cloud_control_plane_change")
            mitre.append(technique)
    if payload.get("mfa_present") is False and signals:
        signals.append("identity_mfa_absent")
    if not signals:
        return []
    return [
        SensorFinding(
            sensor="native_cloud_sensor",
            event_type="cloud_control_plane",
            severity=severity_from_signals(list(dict.fromkeys(signals)), base=3),
            entity_id=resource,
            entity_type="service",
            signals=list(dict.fromkeys(signals)),
            mitre_tags=list(dict.fromkeys(mitre)),
            raw_payload=payload,
            normalized_payload={
                "actor": actor,
                "resource": resource,
                "event_name": event_name,
                "cloud_provider": payload.get("cloud_provider"),
                "region": payload.get("region"),
                "identity_context": {
                    "subject": {"id": actor, "provider": payload.get("cloud_provider", "cloud")},
                    "session": {"mfa_present": payload.get("mfa_present")},
                },
            },
            src_ip=str(payload.get("src_ip")) if payload.get("src_ip") else None,
        )
    ]
