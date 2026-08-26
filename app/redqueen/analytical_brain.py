from __future__ import annotations

from typing import Any

HIGH_IMPACT_MARKERS = {
    "data_exfiltration",
    "lateral_movement",
    "privilege_escalation",
    "credential_attack",
    "ransomware",
    "identity_privileged:true",
    "devsecops_secret_detected:true",
    "devsecops_production_target:true",
    "mcp:critical_dependency",
    "mcp:asset_tier:crown_jewel",
}

NEGATIVE_CONTROL_MARKERS = {
    "identity_mfa:absent",
    "devsecops_deployment_blocked:true",
    "mcp_action_blocked",
    "mcp_tool_denied",
}


def _as_factor_set(factors: list[str]) -> set[str]:
    return {str(item).strip().lower() for item in factors if str(item).strip()}


def _extract_context_signals(controls: dict[str, Any]) -> dict[str, Any]:
    raw_perception = controls.get("perception")
    perception: dict[str, Any] = raw_perception if isinstance(raw_perception, dict) else {}
    raw_risk_drift = controls.get("risk_drift")
    risk_drift: dict[str, Any] = raw_risk_drift if isinstance(raw_risk_drift, dict) else {}
    raw_rag_context = controls.get("rag_context")
    rag_context: dict[str, Any] = raw_rag_context if isinstance(raw_rag_context, dict) else {}
    raw_mcp_context = controls.get("mcp_context")
    mcp_context: dict[str, Any] = raw_mcp_context if isinstance(raw_mcp_context, dict) else {}
    raw_references = rag_context.get("references")
    references: list[Any] = raw_references if isinstance(raw_references, list) else []
    return {
        "source": perception.get("source", ""),
        "entity_type": perception.get("entity_type", ""),
        "drift_severity": risk_drift.get("severity", "none"),
        "rag_reference_count": len(references),
        "mcp_critical_dependency": bool(mcp_context.get("critical_dependency")),
        "mcp_blast_radius": mcp_context.get("blast_radius", ""),
    }


def build_analytical_profile(
    *,
    target: str,
    risk_score: float,
    action_type: str,
    factors: list[str],
    controls: dict[str, Any] | None = None,
) -> dict[str, Any]:
    controls = controls if isinstance(controls, dict) else {}
    normalized_score = max(0.0, min(100.0, float(risk_score or 0.0)))
    factor_set = _as_factor_set(factors)
    high_impact_hits = sorted(
        marker for marker in HIGH_IMPACT_MARKERS if marker.lower() in factor_set
    )
    negative_controls = sorted(
        marker for marker in NEGATIVE_CONTROL_MARKERS if marker.lower() in factor_set
    )
    context_signals = _extract_context_signals(controls)

    evidence_depth = min(
        100.0,
        (len(factor_set) * 4.0)
        + (float(context_signals["rag_reference_count"]) * 8.0)
        + (12.0 if context_signals["mcp_critical_dependency"] else 0.0),
    )
    contradiction_count = 0
    if normalized_score >= 80 and str(action_type) in {"observe", "soar_delegate"}:
        contradiction_count += 1
    if normalized_score < 45 and str(action_type) not in {"observe", "soar_delegate"}:
        contradiction_count += 1
    if negative_controls and str(action_type) not in {"observe", "soar_delegate"}:
        contradiction_count += 1

    diligence_score = max(
        0.0,
        min(
            100.0,
            (normalized_score * 0.45)
            + (evidence_depth * 0.35)
            + (len(high_impact_hits) * 6.0)
            - (contradiction_count * 12.0),
        ),
    )
    if normalized_score >= 90 and high_impact_hits:
        diligence_score = max(diligence_score, 86.0)
    posture = "critical_review" if diligence_score >= 85 else "deep_review"
    if normalized_score >= 90 and high_impact_hits:
        posture = "critical_review"
    if diligence_score < 55:
        posture = "observe_and_collect"

    return {
        "schema": "vaelqorix.redqueen.analytical_brain.v1",
        "target": target,
        "posture": posture,
        "diligence_score": round(diligence_score, 2),
        "evidence_depth": round(evidence_depth, 2),
        "contradiction_count": contradiction_count,
        "high_impact_markers": high_impact_hits,
        "negative_controls": negative_controls,
        "context_signals": context_signals,
        "recommended_guardrails": _recommended_guardrails(
            risk_score=normalized_score,
            contradiction_count=contradiction_count,
            context_signals=context_signals,
        ),
    }


def _recommended_guardrails(
    *,
    risk_score: float,
    contradiction_count: int,
    context_signals: dict[str, Any],
) -> list[str]:
    guardrails: list[str] = []
    if risk_score >= 80:
        guardrails.append("human_approval")
        guardrails.append("rollback_ready")
    if contradiction_count:
        guardrails.append("second_model_or_operator_review")
    if context_signals.get("mcp_critical_dependency"):
        guardrails.append("dependency_owner_review")
    if context_signals.get("rag_reference_count", 0) == 0:
        guardrails.append("collect_more_evidence")
    return list(dict.fromkeys(guardrails))
