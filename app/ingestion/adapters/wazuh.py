from __future__ import annotations

from typing import Any

from app.ingestion.adapters.common import compact_labels, first_value


def adapt_wazuh_event(payload: dict[str, Any]) -> dict[str, Any]:
    rule_id = first_value(payload, ["rule.id", "rule_id"], "unknown-rule")
    rule_level = first_value(payload, ["rule.level", "severity"], "medium")
    agent_name = first_value(payload, ["agent.name", "agent.hostname", "host.name"], "unknown-agent")
    src_ip = first_value(payload, ["data.srcip", "srcip", "source.ip"], "")
    description = first_value(payload, ["rule.description", "full_log", "message"], "Wazuh alert")

    return {
        "source": "wazuh/edr",
        "alertname": first_value(payload, ["rule.groups.0", "rule.mitre.tactic.0"], "WazuhAlert"),
        "title": f"Wazuh {rule_id}: {description}",
        "description": description,
        "severity": _severity_from_wazuh_level(rule_level),
        "category": "edr",
        "target": agent_name,
        "source_ip": src_ip,
        "fingerprint": f"wazuh|{rule_id}|{agent_name}|{src_ip}",
        "event": payload,
        "labels": compact_labels(
            {
                "job": "wazuh",
                "rule_id": rule_id,
                "agent": agent_name,
                "source_ip": src_ip,
            }
        ),
    }


def _severity_from_wazuh_level(level: Any) -> str:
    try:
        numeric = int(level)
    except (TypeError, ValueError):
        return str(level or "medium").lower()
    if numeric >= 12:
        return "critical"
    if numeric >= 8:
        return "high"
    if numeric >= 4:
        return "medium"
    return "low"
