from __future__ import annotations

from typing import Any

from app.sensors.contracts import SensorFinding, severity_from_signals


def collect_k8s_findings(payload: dict[str, Any]) -> list[SensorFinding]:
    verb = str(payload.get("verb") or "").lower()
    resource = str(payload.get("resource") or payload.get("objectRef.resource") or "")
    namespace = str(payload.get("namespace") or payload.get("objectRef.namespace") or "default")
    user = str(payload.get("user") or payload.get("username") or "k8s:unknown")
    pod = str(payload.get("pod") or payload.get("name") or f"{namespace}/{resource}")
    privileged = bool(payload.get("privileged") or payload.get("host_pid") or payload.get("host_network"))
    signals: list[str] = []
    mitre: list[str] = []
    if privileged and resource in {"pods", "pod"}:
        signals.append("k8s_privileged_pod")
        mitre.append("T1611")
    if verb in {"create", "patch", "update"} and resource in {"clusterrolebindings", "roles", "rolebindings"}:
        signals.append("privilege_escalation")
        mitre.append("T1098")
    if verb == "create" and resource in {"secrets", "serviceaccounts"}:
        signals.append("cloud_control_plane_change")
        mitre.append("T1552")
    if not signals:
        return []
    return [
        SensorFinding(
            sensor="native_k8s_sensor",
            event_type="kubernetes_audit",
            severity=severity_from_signals(list(dict.fromkeys(signals)), base=3),
            entity_id=pod,
            entity_type="service",
            signals=list(dict.fromkeys(signals)),
            mitre_tags=list(dict.fromkeys(mitre)),
            raw_payload=payload,
            normalized_payload={
                "namespace": namespace,
                "resource": resource,
                "verb": verb,
                "user": user,
                "privileged": privileged,
                "identity_context": {"subject": {"id": user, "provider": "kubernetes"}},
            },
        )
    ]
