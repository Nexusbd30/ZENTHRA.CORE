from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    name: str
    severity: int
    conditions: dict[str, Any]
    mitre_tags: list[str] = field(default_factory=list)
    kill_chain_stage: str = "unknown"
    recommended_action: str = "observe"


@dataclass(frozen=True)
class DetectionMatch:
    rule_id: str
    name: str
    severity: int
    entity_id: str
    entity_type: str
    signals: list[str]
    mitre_tags: list[str]
    kill_chain_stage: str
    recommended_action: str
    evidence: dict[str, Any]

    def asdict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "signals": self.signals,
            "mitre_tags": self.mitre_tags,
            "kill_chain_stage": self.kill_chain_stage,
            "recommended_action": self.recommended_action,
            "evidence": self.evidence,
        }


BUILTIN_RULES = [
    DetectionRule(
        rule_id="VXDR-ENDPOINT-001",
        name="Credential dumping process on endpoint",
        severity=9,
        conditions={"signals_any": ["credential_dumping"]},
        mitre_tags=["T1003"],
        kill_chain_stage="credential_access",
        recommended_action="endpoint_isolate",
    ),
    DetectionRule(
        rule_id="VXDR-NETWORK-001",
        name="Outbound callback with suspicious DNS or port",
        severity=8,
        conditions={"signals_any": ["dns_callback", "outbound_callback"]},
        mitre_tags=["T1071", "T1105"],
        kill_chain_stage="command_and_control",
        recommended_action="aggressive_containment",
    ),
    DetectionRule(
        rule_id="VXDR-LATERAL-001",
        name="Lateral movement fan-out",
        severity=9,
        conditions={"signals_all": ["lateral_movement"]},
        mitre_tags=["T1021"],
        kill_chain_stage="lateral_movement",
        recommended_action="network_isolate",
    ),
    DetectionRule(
        rule_id="VXDR-K8S-001",
        name="Privileged Kubernetes workload",
        severity=8,
        conditions={"signals_any": ["k8s_privileged_pod", "privilege_escalation"]},
        mitre_tags=["T1611", "T1098"],
        kill_chain_stage="privilege_escalation",
        recommended_action="aggressive_containment",
    ),
    DetectionRule(
        rule_id="VXDR-CLOUD-001",
        name="High risk cloud control-plane change",
        severity=8,
        conditions={"signals_any": ["cloud_control_plane_change"]},
        mitre_tags=["T1098", "T1562"],
        kill_chain_stage="persistence",
        recommended_action="identity_lockdown",
    ),
]


def _signals(event: dict[str, Any]) -> set[str]:
    payload = event.get("normalized_payload")
    payload = payload if isinstance(payload, dict) else {}
    raw = event.get("signals") or payload.get("sensor_signals") or []
    return {str(item).strip().lower() for item in raw if str(item).strip()}


def _matches(rule: DetectionRule, signals: set[str]) -> bool:
    any_values = {
        str(item).lower()
        for item in rule.conditions.get("signals_any", [])
        if str(item).strip()
    }
    all_values = {
        str(item).lower()
        for item in rule.conditions.get("signals_all", [])
        if str(item).strip()
    }
    return (not any_values or bool(signals & any_values)) and all_values.issubset(signals)


def evaluate_rules(events: list[dict[str, Any]], rules: list[DetectionRule] | None = None) -> list[dict[str, Any]]:
    active_rules = rules or BUILTIN_RULES
    matches: list[DetectionMatch] = []
    for event in events:
        signals = _signals(event)
        for rule in active_rules:
            if _matches(rule, signals):
                matches.append(
                    DetectionMatch(
                        rule_id=rule.rule_id,
                        name=rule.name,
                        severity=rule.severity,
                        entity_id=str(event.get("entity_id") or "unknown"),
                        entity_type=str(event.get("entity_type") or "unknown"),
                        signals=sorted(signals),
                        mitre_tags=rule.mitre_tags,
                        kill_chain_stage=rule.kill_chain_stage,
                        recommended_action=rule.recommended_action,
                        evidence={"event_id": event.get("event_id"), "source": event.get("source")},
                    )
                )
    return [match.asdict() for match in matches]
