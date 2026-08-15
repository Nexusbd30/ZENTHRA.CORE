from __future__ import annotations

from typing import Any

CONTROL_MAP = {
    "SOC2_CC6": ["rbac", "least_privilege", "audit_chain"],
    "SOC2_CC7": ["detection", "incident_response", "monitoring"],
    "ISO27001_A5_24": ["incident_response_planning", "legal_escalation_pack"],
    "ISO27001_A8_16": ["monitoring", "siem_export", "xdr_correlation"],
    "ISO27001_A8_20": ["network_security", "perimeter_auto_block"],
}


def compliance_evidence_snapshot(system_status: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "vaelqorix.compliance.evidence.v1",
        "frameworks": ["SOC2", "ISO27001"],
        "controls": [
            {"control": control, "mapped_capabilities": capabilities}
            for control, capabilities in CONTROL_MAP.items()
        ],
        "system_status": system_status,
    }
