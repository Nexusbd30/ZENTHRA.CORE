from __future__ import annotations

from typing import Any


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def build_causal_chain(
    *,
    target: str,
    risk_score: float,
    action_type: str,
    perception: dict[str, Any] | None = None,
    factors: list[str] | None = None,
    llm_reasoning: str = "",
) -> dict[str, Any]:
    perception = perception or {}
    metadata = _dict(perception.get("metadata"))
    labels = _dict(perception.get("labels"))
    annotations = _dict(perception.get("annotations"))
    factors = factors or []

    observed_signals = [
        value
        for value in [
            perception.get("title"),
            annotations.get("summary"),
            labels.get("alertname"),
            f"severity={perception.get('level')}" if perception.get("level") else None,
            f"category={perception.get('category')}" if perception.get("category") else None,
            f"status={metadata.get('status')}" if metadata.get("status") else None,
            f"occurrences={metadata.get('occurrences')}" if metadata.get("occurrences") else None,
        ]
        if value
    ]

    if risk_score >= 90:
        impact = "posible compromiso critico o propagacion lateral con impacto alto"
    elif risk_score >= 75:
        impact = "riesgo alto sobre identidad, endpoint o servicio sensible"
    elif risk_score >= 50:
        impact = "riesgo operativo moderado que requiere contencion coordinada"
    else:
        impact = "riesgo bajo o incierto que requiere observacion"

    if action_type == "network_isolate":
        action_rationale = "aislar red reduce movimiento lateral y exfiltracion"
    elif action_type == "identity_lockdown":
        action_rationale = "bloquear identidad reduce abuso de credenciales"
    elif action_type == "endpoint_isolate":
        action_rationale = "aislar endpoint contiene ejecucion y preserva evidencia"
    elif action_type == "soar_delegate":
        action_rationale = "delegar a SOAR coordina respuesta sin accion disruptiva directa"
    else:
        action_rationale = "observar mantiene trazabilidad sin impacto operativo"

    return {
        "target": target,
        "cause": observed_signals or factors or ["baseline_risk_assessment"],
        "impact": impact,
        "action": action_type,
        "action_rationale": action_rationale,
        "llm_reasoning": llm_reasoning,
        "confidence_notes": [
            "risk_score_normalized",
            "policy_matrix_applied",
            "minimum_action_floor_enforced",
        ],
    }
