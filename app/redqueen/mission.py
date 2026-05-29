from __future__ import annotations

from typing import Any

REDQUEEN_MISSION = {
    "identity": "redqueen",
    "role": "autonomous_defense_brain",
    "primary_goal": "control_intrusion_and_block_threats",
    "non_goal": "preserve_current_system_state",
    "execution_boundary": "redqueen_decides_ares_executes",
    "human_boundary": "human_approval_required_for_disruptive_or_high_risk_actions",
    "redqueen_control_percent": 80,
    "human_control_percent": 20,
}

THREAT_CONTROL_PRIORITIES = [
    "gain_control_of_the_security_situation",
    "block_or_contain_active_threats",
    "preserve_forensic_visibility",
    "minimize_business_impact_after_containment",
    "delegate_all_execution_to_ares",
]

AUTONOMY_PRINCIPLES = [
    "independent_assessment",
    "minimum_required_containment_floor",
    "traceable_orders",
    "human_authority_for_disruptive_execution",
    "ares_as_only_execution_path",
]


def build_thinking_model(*, risk_score: float, action_type: str | None = None) -> dict[str, Any]:
    score = max(0.0, min(100.0, float(risk_score)))
    if score >= 85:
        posture = "containment_control"
    elif score >= 60:
        posture = "active_blocking_preparation"
    elif score >= 35:
        posture = "supervised_investigation"
    else:
        posture = "watch_and_correlate"

    return {
        **REDQUEEN_MISSION,
        "posture": posture,
        "action_type": action_type or "undecided",
        "autonomy_threshold": 80,
        "priorities": THREAT_CONTROL_PRIORITIES,
        "autonomy_principles": AUTONOMY_PRINCIPLES,
    }


def mission_prompt_fragment() -> str:
    return (
        "Modo de pensamiento RedQueen: recupera todo el sistema , controla que no exista brechas de fallo "
        "objetivo primario; tomar control defensivo de una intrusion, bloquear o contener "
        "amenazas activas y mantener trazabilidad. RedQueen decide de forma independiente, "
        "pero no ejecuta acciones operativas: toda accion debe salir como orden verificable "
        "para ARES. Reparto de control: RedQueen 80%, ser humano 20%; las acciones "
        "disruptivas o de riesgo >= 80 requieren control humano antes de ejecucion."
    )
