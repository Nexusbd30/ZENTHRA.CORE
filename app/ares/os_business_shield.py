from __future__ import annotations

from typing import Any


def build_os_business_shield(
    *,
    target: str,
    action_type: str,
    anticipation: dict[str, Any] | None = None,
    controls: dict[str, Any] | None = None,
) -> dict[str, Any]:
    anticipation = anticipation if isinstance(anticipation, dict) else {}
    controls = controls if isinstance(controls, dict) else {}
    preventive_controls = [
        str(item)
        for item in anticipation.get("preventive_controls", [])
        if str(item).strip()
    ]
    stages = [str(item) for item in anticipation.get("attack_stages", []) if str(item).strip()]
    shield_layers = _shield_layers(preventive_controls, stages)
    protected_targets = []
    firewall_policy = controls.get("firewall_policy")
    if isinstance(firewall_policy, dict) and isinstance(firewall_policy.get("protected_targets"), list):
        protected_targets = [str(item) for item in firewall_policy["protected_targets"] if item]

    return {
        "schema": "vaelqorix.ares.os_business_shield.v1",
        "target": target,
        "action_type": action_type,
        "mode": "preventive_defense",
        "attack_horizon": anticipation.get("horizon", "unknown"),
        "latest_stage": anticipation.get("latest_stage", "unknown"),
        "shield_layers": shield_layers,
        "protected_targets": protected_targets,
        "guardrails": _guardrails(action_type=action_type, controls=controls, layers=shield_layers),
    }


def _shield_layers(preventive_controls: list[str], stages: list[str]) -> list[dict[str, Any]]:
    layers: list[dict[str, Any]] = []
    if any(item in preventive_controls for item in {"require_mfa", "revoke_suspicious_sessions"}):
        layers.append(
            {
                "layer": "identity",
                "controls": [
                    item
                    for item in preventive_controls
                    if item in {"require_mfa", "revoke_suspicious_sessions", "review_admin_groups"}
                ],
            }
        )
    if any(item in preventive_controls for item in {"segment_network", "tighten_east_west_rules"}):
        layers.append(
            {
                "layer": "network",
                "controls": [
                    item
                    for item in preventive_controls
                    if item in {"segment_network", "tighten_east_west_rules", "block_suspicious_egress"}
                ],
            }
        )
    if any(item in preventive_controls for item in {"collect_forensics", "isolate_endpoint_if_confirmed"}):
        layers.append(
            {
                "layer": "endpoint",
                "controls": [
                    item
                    for item in preventive_controls
                    if item in {"collect_forensics", "isolate_endpoint_if_confirmed"}
                ],
            }
        )
    if any(item in preventive_controls for item in {"protect_sensitive_data_paths", "rotate_exposed_secret"}):
        layers.append(
            {
                "layer": "data",
                "controls": [
                    item
                    for item in preventive_controls
                    if item in {"protect_sensitive_data_paths", "rotate_exposed_secret"}
                ],
            }
        )
    if any(item in preventive_controls for item in {"freeze_high_risk_change", "block_release_until_review"}):
        layers.append(
            {
                "layer": "business_change",
                "controls": [
                    item
                    for item in preventive_controls
                    if item in {"freeze_high_risk_change", "block_release_until_review"}
                ],
            }
        )
    if not layers:
        layers.append({"layer": "monitoring", "controls": ["increase_monitoring", "preserve_evidence"]})
    for layer in layers:
        layer["attack_stages"] = stages
    return layers


def _guardrails(
    *,
    action_type: str,
    controls: dict[str, Any],
    layers: list[dict[str, Any]],
) -> list[str]:
    guardrails = ["audit_required", "operator_visibility"]
    if action_type not in {"observe", "soar_delegate", "system_harden"}:
        guardrails.append("human_approval_for_disruptive_change")
    if any(layer["layer"] in {"network", "identity", "business_change"} for layer in layers):
        guardrails.append("rollback_or_change_ticket_required")
    if controls.get("dependency_owner_approved"):
        guardrails.append("dependency_owner_approved")
    return list(dict.fromkeys(guardrails))
