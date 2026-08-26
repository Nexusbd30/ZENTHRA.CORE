from __future__ import annotations

from typing import Any

from app.sensors.contracts import SensorFinding, severity_from_signals


def collect_network_findings(payload: dict[str, Any]) -> list[SensorFinding]:
    src_ip = str(payload.get("src_ip") or payload.get("source_ip") or "")
    dst_ip = str(payload.get("dst_ip") or payload.get("destination_ip") or "")
    dst_port = int(payload.get("dst_port") or payload.get("destination_port") or 0)
    dns_query = str(payload.get("dns_query") or payload.get("domain") or "")
    connection_count = int(payload.get("connection_count") or 1)
    unique_hosts = int(payload.get("unique_hosts") or 1)
    signals: list[str] = []
    mitre: list[str] = []
    if dns_query and any(token in dns_query.lower() for token in ("dga", "callback", "beacon")):
        signals.append("dns_callback")
        mitre.append("T1071")
    if dst_port in {4444, 8080, 8443, 9001} and connection_count >= 3:
        signals.append("outbound_callback")
        mitre.append("T1105")
    if unique_hosts >= 10 or payload.get("east_west") is True:
        signals.append("lateral_movement")
        mitre.append("T1021")
    if not signals:
        return []
    return [
        SensorFinding(
            sensor="native_network_sensor",
            event_type="network_behavior",
            severity=severity_from_signals(list(dict.fromkeys(signals)), base=2),
            entity_id=src_ip or "network:unknown",
            entity_type="network",
            signals=list(dict.fromkeys(signals)),
            mitre_tags=list(dict.fromkeys(mitre)),
            raw_payload=payload,
            normalized_payload={
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "dns_query": dns_query,
                "connection_count": connection_count,
                "unique_hosts": unique_hosts,
                "asn": payload.get("asn"),
                "geo_country": payload.get("geo_country"),
                "domain": dns_query,
            },
            src_ip=src_ip or None,
            dst_ip=dst_ip or None,
            geo_country=str(payload.get("geo_country")) if payload.get("geo_country") else None,
        )
    ]
