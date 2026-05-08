from __future__ import annotations

from typing import Any

from app.ingestion.adapters.common import compact_labels, first_value


def adapt_netflow_event(payload: dict[str, Any]) -> dict[str, Any]:
    src_ip = first_value(payload, ["src_ip", "source_ip", "source.ip"], "")
    dst_ip = first_value(payload, ["dst_ip", "destination_ip", "destination.ip"], "unknown-destination")
    dst_port = first_value(payload, ["dst_port", "destination_port", "destination.port"], "")
    bytes_out = first_value(payload, ["bytes", "bytes_out", "network.bytes"], 0)
    protocol = first_value(payload, ["protocol", "network.protocol"], "")

    return {
        "source": "netflow",
        "alertname": "NetworkFlowAnomaly",
        "title": f"Network flow anomaly to {dst_ip}",
        "description": f"Network flow from {src_ip or 'unknown'} to {dst_ip}:{dst_port}",
        "severity": _severity_from_bytes(bytes_out),
        "category": "network",
        "target": str(dst_ip),
        "source_ip": src_ip,
        "fingerprint": f"netflow|{src_ip}|{dst_ip}|{dst_port}|{protocol}",
        "event": payload,
        "labels": compact_labels(
            {
                "job": "netflow",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "protocol": protocol,
            }
        ),
    }


def _severity_from_bytes(value: Any) -> str:
    try:
        byte_count = int(value)
    except (TypeError, ValueError):
        return "medium"
    if byte_count >= 10_000_000_000:
        return "critical"
    if byte_count >= 1_000_000_000:
        return "high"
    if byte_count >= 100_000_000:
        return "medium"
    return "low"
