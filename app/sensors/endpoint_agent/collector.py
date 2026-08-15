from __future__ import annotations

from typing import Any

from app.sensors.contracts import SensorFinding, severity_from_signals

SUSPICIOUS_PROCESS_MARKERS = {
    "mimikatz": ("credential_dumping", "T1003"),
    "procdump": ("credential_dumping", "T1003"),
    "powershell -enc": ("suspicious_process", "T1059"),
    "certutil -urlcache": ("suspicious_process", "T1105"),
    "rundll32": ("suspicious_process", "T1218"),
}


def collect_endpoint_findings(payload: dict[str, Any]) -> list[SensorFinding]:
    host = str(payload.get("host") or payload.get("hostname") or payload.get("entity_id") or "host:unknown")
    process = str(payload.get("process") or payload.get("process_name") or "")
    command_line = str(payload.get("command_line") or payload.get("cmdline") or process)
    file_path = str(payload.get("file_path") or "")
    auth_failures = int(payload.get("auth_failures") or 0)
    lower = f"{process} {command_line}".lower()
    signals: list[str] = []
    mitre: list[str] = []
    for marker, (signal, technique) in SUSPICIOUS_PROCESS_MARKERS.items():
        if marker in lower:
            signals.append(signal)
            mitre.append(technique)
    if payload.get("outbound_ip") or payload.get("outbound_domain"):
        signals.append("outbound_callback")
        mitre.append("T1105")
    if file_path.lower() in {"/etc/shadow", "c:\\windows\\system32\\config\\sam"}:
        signals.append("critical_file_change")
        mitre.append("T1003")
    if auth_failures >= 5:
        signals.append("local_auth_failure_burst")
        mitre.append("T1110")
    if not signals:
        return []
    return [
        SensorFinding(
            sensor="native_endpoint_agent",
            event_type="endpoint_behavior",
            severity=severity_from_signals(list(dict.fromkeys(signals)), base=2),
            entity_id=host,
            entity_type="host",
            signals=list(dict.fromkeys(signals)),
            mitre_tags=list(dict.fromkeys(mitre)),
            raw_payload=payload,
            normalized_payload={
                "host": host,
                "process": process,
                "command_line": command_line,
                "file_path": file_path,
                "outbound_ip": payload.get("outbound_ip"),
                "outbound_domain": payload.get("outbound_domain"),
            },
            dst_ip=str(payload.get("outbound_ip")) if payload.get("outbound_ip") else None,
        )
    ]
