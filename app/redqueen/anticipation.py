from __future__ import annotations

from typing import Any

ATTACK_STAGE_MARKERS: dict[str, tuple[str, str]] = {
    "exposed_to_internet": ("reconnaissance", "internet_exposure"),
    "credential_attack": ("initial_access", "credential_abuse"),
    "credential_stuffing": ("initial_access", "credential_abuse"),
    "bruteforce": ("initial_access", "credential_abuse"),
    "identity_mfa:absent": ("initial_access", "weak_authentication"),
    "privilege_escalation": ("privilege_escalation", "privilege_expansion"),
    "identity_privileged:true": ("privilege_escalation", "privileged_identity"),
    "lateral_movement": ("lateral_movement", "east_west_movement"),
    "endpoint_compromise": ("execution", "host_compromise"),
    "malware": ("execution", "malware_execution"),
    "ransomware": ("impact", "ransomware_impact"),
    "data_exfiltration": ("exfiltration", "data_loss"),
    "devsecops_secret_detected:true": ("initial_access", "secret_exposure"),
    "devsecops_production_target:true": ("impact", "production_release_risk"),
    "mcp:critical_dependency": ("impact", "critical_dependency_risk"),
    "mcp:asset_tier:crown_jewel": ("impact", "crown_jewel_risk"),
}

STAGE_ORDER = {
    "reconnaissance": 1,
    "initial_access": 2,
    "execution": 3,
    "privilege_escalation": 4,
    "lateral_movement": 5,
    "exfiltration": 6,
    "impact": 7,
}


def _normalized_factors(values: list[str]) -> set[str]:
    factors = {str(item).strip().lower() for item in values if str(item).strip()}
    expanded = set(factors)
    for item in factors:
        expanded.update(part for part in item.replace("_", " ").replace(":", " ").split() if part)
    return expanded


def _perception_targets(perception: dict[str, Any], target: str) -> list[str]:
    candidates = [
        target,
        perception.get("target"),
        perception.get("target_service"),
        perception.get("database_host"),
        perception.get("entity_id"),
    ]
    return list(dict.fromkeys(str(item) for item in candidates if item))


def anticipate_attack_path(
    *,
    target: str,
    risk_score: float,
    factors: list[str],
    controls: dict[str, Any] | None = None,
) -> dict[str, Any]:
    controls = controls if isinstance(controls, dict) else {}
    raw_perception = controls.get("perception")
    perception: dict[str, Any] = raw_perception if isinstance(raw_perception, dict) else {}
    raw_mcp_context = controls.get("mcp_context")
    mcp_context: dict[str, Any] = raw_mcp_context if isinstance(raw_mcp_context, dict) else {}
    factor_set = _normalized_factors(factors)
    if mcp_context.get("exposed_to_internet"):
        factor_set.add("exposed_to_internet")
    if mcp_context.get("critical_dependency"):
        factor_set.add("mcp:critical_dependency")
    if str(mcp_context.get("asset_tier", "")).lower() == "crown_jewel":
        factor_set.add("mcp:asset_tier:crown_jewel")

    matched = [
        {
            "marker": marker,
            "stage": stage,
            "risk": risk,
        }
        for marker, (stage, risk) in ATTACK_STAGE_MARKERS.items()
        if marker in factor_set
    ]
    stages = sorted({item["stage"] for item in matched}, key=lambda item: STAGE_ORDER[item])
    latest_stage = stages[-1] if stages else "unknown"
    normalized_score = max(0.0, min(100.0, float(risk_score or 0.0)))
    confidence = min(0.98, 0.35 + (len(matched) * 0.08) + (normalized_score / 250.0))
    if latest_stage in {"exfiltration", "impact"}:
        horizon = "immediate"
    elif latest_stage in {"privilege_escalation", "lateral_movement"}:
        horizon = "near_term"
    elif latest_stage == "unknown":
        horizon = "observe"
    else:
        horizon = "early"

    return {
        "schema": "vaelqorix.redqueen.attack_anticipation.v1",
        "target": target,
        "predicted_targets": _perception_targets(perception, target),
        "risk_score": normalized_score,
        "confidence": round(confidence, 2),
        "horizon": horizon,
        "latest_stage": latest_stage,
        "attack_stages": stages,
        "matched_markers": matched,
        "early_warnings": _early_warnings(matched, factor_set),
        "preventive_controls": _preventive_controls(stages, factor_set),
    }


def _early_warnings(matched: list[dict[str, str]], factor_set: set[str]) -> list[str]:
    warnings = [f"marker:{item['marker']}" for item in matched]
    if "identity_mfa:absent" in factor_set:
        warnings.append("mfa_absent_on_risky_identity")
    if "devsecops_secret_detected:true" in factor_set:
        warnings.append("pipeline_secret_exposure")
    if "mcp:critical_dependency" in factor_set:
        warnings.append("critical_dependency_in_blast_radius")
    return list(dict.fromkeys(warnings))


def _preventive_controls(stages: list[str], factor_set: set[str]) -> list[str]:
    controls: list[str] = ["increase_monitoring", "preserve_evidence"]
    if "initial_access" in stages or "identity_mfa:absent" in factor_set:
        controls.extend(["require_mfa", "revoke_suspicious_sessions"])
    if "privilege_escalation" in stages:
        controls.extend(["degrade_privileges", "review_admin_groups"])
    if "lateral_movement" in stages:
        controls.extend(["segment_network", "tighten_east_west_rules"])
    if "execution" in stages:
        controls.extend(["isolate_endpoint_if_confirmed", "collect_forensics"])
    if "exfiltration" in stages:
        controls.extend(["block_suspicious_egress", "protect_sensitive_data_paths"])
    if "impact" in stages:
        controls.extend(["freeze_high_risk_change", "activate_incident_command"])
    if "devsecops_secret_detected:true" in factor_set:
        controls.extend(["rotate_exposed_secret", "block_release_until_review"])
    return list(dict.fromkeys(controls))
