from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class SensorFinding:
    sensor: str
    event_type: str
    severity: int
    entity_id: str
    entity_type: str
    signals: list[str] = field(default_factory=list)
    mitre_tags: list[str] = field(default_factory=list)
    raw_payload: dict[str, Any] = field(default_factory=dict)
    normalized_payload: dict[str, Any] = field(default_factory=dict)
    src_ip: str | None = None
    dst_ip: str | None = None
    geo_country: str | None = None
    event_id: str = field(default_factory=lambda: uuid4().hex)
    occurred_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_aresx_event(self) -> dict[str, Any]:
        return {
            "source": self.sensor,
            "event_id": self.event_id,
            "occurred_at": self.occurred_at,
            "event_type": self.event_type,
            "severity": max(1, min(10, int(self.severity))),
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "mitre_tags": self.mitre_tags,
            "raw_payload": self.raw_payload,
            "normalized_payload": {
                **self.normalized_payload,
                "sensor_signals": self.signals,
                "provider_evidence": {
                    "kind": "native_sensor_finding",
                    "sensor": self.sensor,
                    "event_id": self.event_id,
                },
            },
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "geo_country": self.geo_country,
        }

    def asdict(self) -> dict[str, Any]:
        return asdict(self)


def severity_from_signals(signals: list[str], *, base: int = 2) -> int:
    weights = {
        "suspicious_process": 3,
        "credential_dumping": 5,
        "outbound_callback": 4,
        "dns_callback": 4,
        "critical_file_change": 4,
        "local_auth_failure_burst": 3,
        "lateral_movement": 5,
        "k8s_privileged_pod": 4,
        "cloud_control_plane_change": 4,
    }
    score = base + sum(weights.get(signal, 1) for signal in signals)
    return max(1, min(10, score))
