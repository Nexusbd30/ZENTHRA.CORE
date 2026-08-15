from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.security import require_admin_or_monitor_token
from app.sensors.cloud_sensor import collect_cloud_findings
from app.sensors.endpoint_agent import collect_endpoint_findings
from app.sensors.k8s_sensor import collect_k8s_findings
from app.sensors.network_sensor import collect_network_findings

router = APIRouter(
    prefix="/api/v1/sensors",
    tags=["sensors"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


class SensorNormalizeRequest(BaseModel):
    sensor: str = Field(..., min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)


COLLECTORS = {
    "endpoint": collect_endpoint_findings,
    "endpoint_agent": collect_endpoint_findings,
    "network": collect_network_findings,
    "network_sensor": collect_network_findings,
    "cloud": collect_cloud_findings,
    "cloud_sensor": collect_cloud_findings,
    "k8s": collect_k8s_findings,
    "kubernetes": collect_k8s_findings,
    "k8s_sensor": collect_k8s_findings,
}


@router.get("/status")
def sensor_status():
    return {
        "status": "enabled",
        "sensors": sorted(COLLECTORS),
        "capabilities": [
            "suspicious_processes",
            "outbound_connections",
            "dns_callbacks",
            "critical_file_changes",
            "local_auth_events",
            "lateral_movement",
            "netflow_enrichment",
            "kubernetes_audit_logs",
            "cloud_control_plane_events",
        ],
    }


@router.post("/normalize")
def normalize_sensor_event(payload: SensorNormalizeRequest):
    collector = COLLECTORS.get(payload.sensor.strip().lower())
    if collector is None:
        return {"status": "unsupported_sensor", "sensor": payload.sensor, "findings": []}
    findings = collector(payload.payload)
    return {
        "status": "ok",
        "sensor": payload.sensor,
        "count": len(findings),
        "findings": [finding.asdict() for finding in findings],
        "aresx_events": [finding.to_aresx_event() for finding in findings],
    }
