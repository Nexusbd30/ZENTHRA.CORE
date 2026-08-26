from __future__ import annotations

from typing import Any

from app.detection.correlation import correlate_detections
from app.detection.rules import evaluate_rules
from app.redqueen.anticipation import STAGE_ORDER

STRATEGIC_SCHEMA = "vaelqorix.redqueen.strategic_anticipation.v1"


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _factor_set(factors: list[str]) -> set[str]:
    return {str(item).strip().lower() for item in factors if str(item).strip()}


def _stage_velocity(stages: list[str], factors: set[str], risk_score: float) -> str:
    stage_count = len(stages)
    has_late_stage = bool({"lateral_movement", "exfiltration", "impact"} & set(stages))
    if risk_score >= 90 or (has_late_stage and stage_count >= 3) or "ransomware" in factors:
        return "breakout_imminent"
    if risk_score >= 75 or has_late_stage:
        return "accelerating"
    if risk_score >= 55 or stage_count >= 2:
        return "forming"
    return "watch"


def _intervention_window(velocity: str, horizon: str) -> str:
    if velocity == "breakout_imminent" or horizon == "immediate":
        return "0-15m"
    if velocity == "accelerating" or horizon == "near_term":
        return "15-60m"
    if velocity == "forming":
        return "1-4h"
    return "monitor"


def _business_priority(controls: dict[str, Any], risk_score: float) -> str:
    mcp_context = _dict(controls.get("mcp_context"))
    asset_tier = str(mcp_context.get("asset_tier") or "").lower()
    blast_radius = str(mcp_context.get("blast_radius") or "").lower()
    if asset_tier == "crown_jewel" or blast_radius in {"enterprise", "global"} or risk_score >= 90:
        return "protect_crown_jewels"
    if mcp_context.get("critical_dependency") or risk_score >= 75:
        return "protect_business_service"
    return "protect_entity"


def _next_best_actions(
    *,
    stages: list[str],
    factors: set[str],
    bridge_trace: dict[str, Any],
    risk_score: float,
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = [
        {
            "action": "preserve_evidence",
            "reason": "maintain_chain_of_custody",
            "urgency": "immediate",
            "provider_family": "case",
        }
    ]
    block_targets = _list(bridge_trace.get("block_targets"))
    if block_targets:
        actions.append(
            {
                "action": "block_observed_indicators",
                "reason": "bridge_trace_has_block_targets",
                "urgency": "immediate" if risk_score >= 80 else "near_term",
                "provider_family": "firewall_waf_ndr",
            }
        )
    if "initial_access" in stages or "credential_attack" in factors:
        actions.append(
            {
                "action": "revoke_sessions_and_tokens",
                "reason": "credential_or_session_bridge_possible",
                "urgency": "immediate",
                "provider_family": "iam_idp",
            }
        )
    if "execution" in stages or "lateral_movement" in stages:
        actions.append(
            {
                "action": "isolate_confirmed_endpoint",
                "reason": "execution_or_lateral_movement_observed",
                "urgency": "immediate",
                "provider_family": "edr_kubernetes_cloud",
            }
        )
    if "impact" in stages or "devsecops_secret_detected:true" in factors:
        actions.append(
            {
                "action": "freeze_release_path",
                "reason": "production_or_supply_chain_impact_possible",
                "urgency": "near_term",
                "provider_family": "scm_ci_artifact_registry",
            }
        )
    if risk_score >= 70:
        actions.append(
            {
                "action": "deploy_detection_and_deception",
                "reason": "increase_attacker_visibility_inside_owned_assets",
                "urgency": "near_term",
                "provider_family": "waf_edr_siem_soar",
            }
        )
    return list({f"{item['action']}:{item['provider_family']}": item for item in actions}.values())


def build_strategic_anticipation(
    *,
    target: str,
    risk_score: float,
    factors: list[str],
    anticipation: dict[str, Any],
    bridge_trace: dict[str, Any],
    controls: dict[str, Any] | None = None,
) -> dict[str, Any]:
    controls = controls if isinstance(controls, dict) else {}
    normalized_score = max(0.0, min(100.0, float(risk_score or 0.0)))
    stages = [
        str(item)
        for item in anticipation.get("attack_stages", [])
        if str(item) in STAGE_ORDER
    ]
    stages = sorted(set(stages), key=lambda item: STAGE_ORDER[item])
    factors_set = _factor_set(factors)
    sensor_events = [item for item in _list(controls.get("sensor_events")) if isinstance(item, dict)]
    detection_matches = evaluate_rules(sensor_events) if sensor_events else []
    correlation = correlate_detections(detection_matches) if detection_matches else {
        "schema": "vaelqorix.detection.correlation.v1",
        "incident_count": 0,
        "incidents": [],
    }
    for incident in correlation.get("incidents", []):
        for stage in incident.get("kill_chain_stages", []):
            if stage in STAGE_ORDER:
                stages.append(stage)
    stages = sorted(set(stages), key=lambda item: STAGE_ORDER[item])
    velocity = _stage_velocity(stages, factors_set, normalized_score)
    intervention_window = _intervention_window(velocity, str(anticipation.get("horizon") or "observe"))
    next_best_actions = _next_best_actions(
        stages=stages,
        factors=factors_set,
        bridge_trace=bridge_trace,
        risk_score=normalized_score,
    )
    confidence = min(
        0.99,
        float(anticipation.get("confidence") or 0.0)
        + (0.04 * len(detection_matches))
        + (0.03 * len(bridge_trace.get("block_targets", []))),
    )
    return {
        "schema": STRATEGIC_SCHEMA,
        "target": target,
        "risk_score": normalized_score,
        "confidence": round(confidence, 2),
        "business_priority": _business_priority(controls, normalized_score),
        "stage_velocity": velocity,
        "intervention_window": intervention_window,
        "predicted_attack_path": stages,
        "detection_correlation": correlation,
        "next_best_actions": next_best_actions,
        "decision_advantage": {
            "blocks_before_impact": intervention_window != "monitor",
            "uses_native_telemetry": bool(sensor_events),
            "uses_bridge_trace": bool(bridge_trace.get("block_targets")),
            "governed_active_defense": True,
        },
        "boundaries": [
            "owned_assets_only",
            "no_hack_back",
            "human_approval_for_disruptive_actions",
        ],
    }
