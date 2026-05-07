from __future__ import annotations

import json
from typing import Any

from app.core.ai_provider import ai_provider
from app.core.mcp_context import normalize_mcp_context

ARES_ADVISOR_SYSTEM_PROMPT = """
Eres ARES Advisor, revisor tactico de ejecucion defensiva.
Tu salida debe ser SOLO JSON valido:
{
  "risk": "low|medium|high|critical",
  "safe_to_execute": true|false,
  "required_safeguards": ["..."],
  "operator_notes": "...",
  "mcp_used": true|false
}
Reglas:
- No puedes aprobar acciones que violen policy, firma, kill-switch o trazabilidad.
- Si falta contexto, recomienda dry_run o aprobacion humana.
- Usa contexto MCP si esta presente.
""".strip()


def _risk_from_plan(plan: dict[str, Any]) -> str:
    max_criticality = int(plan.get("max_criticality", 0) or 0)
    if max_criticality >= 5:
        return "critical"
    if max_criticality >= 4:
        return "high"
    if max_criticality >= 2:
        return "medium"
    return "low"


def review_plan(
    *,
    verdict: dict[str, Any],
    plan: dict[str, Any],
    controls: dict[str, Any] | None = None,
) -> dict[str, Any]:
    controls = controls or {}
    raw_mcp_context = controls.get("mcp_context") if isinstance(controls.get("mcp_context"), dict) else {}
    mcp_context = normalize_mcp_context(raw_mcp_context, target=str(plan.get("target") or ""))
    prompt_payload = {
        "verdict": {
            "verdict_id": verdict.get("verdict_id"),
            "target": verdict.get("target"),
            "action_type": verdict.get("action_type"),
            "risk_score": verdict.get("risk_score"),
            "requires_human": verdict.get("requires_human"),
            "causal_chain": verdict.get("causal_chain", {}),
        },
        "plan": {
            "action_type": plan.get("action_type"),
            "target": plan.get("target"),
            "max_criticality": plan.get("max_criticality"),
            "requires_confirmation": plan.get("requires_confirmation"),
            "rollback_strategy": plan.get("rollback_strategy"),
            "steps": plan.get("steps", []),
        },
        "controls": {
            "dry_run": bool(controls.get("dry_run", False)),
            "change_ticket_present": bool(controls.get("change_ticket")),
            "threat_id_present": bool(controls.get("threat_id")),
        },
        "mcp_context": mcp_context,
    }

    raw = ai_provider.complete(
        ARES_ADVISOR_SYSTEM_PROMPT,
        json.dumps(prompt_payload, ensure_ascii=False, sort_keys=True),
    )
    parsed = ai_provider.parse_json(raw)
    fallback_risk = _risk_from_plan(plan)

    required_safeguards = parsed.get("required_safeguards")
    if not isinstance(required_safeguards, list):
        required_safeguards = []

    if plan.get("requires_confirmation"):
        required_safeguards.append("operator_confirmation")
    if plan.get("rollback_strategy") != "none":
        required_safeguards.append("rollback_ready")
    if controls.get("dry_run"):
        required_safeguards.append("dry_run_only")
    if mcp_context:
        required_safeguards.append("mcp_context_reviewed")
    if mcp_context.get("critical_dependency"):
        required_safeguards.append("dependency_owner_review")
    if mcp_context.get("blocked_actions"):
        required_safeguards.append("blocked_action_policy_review")

    return {
        "provider": "llm",
        "risk": str(parsed.get("risk") or fallback_risk),
        "safe_to_execute": bool(parsed.get("safe_to_execute", fallback_risk not in {"critical"})),
        "required_safeguards": list(dict.fromkeys(str(item) for item in required_safeguards if item)),
        "operator_notes": str(parsed.get("operator_notes") or "ARES advisor fallback review applied"),
        "mcp_used": bool(parsed.get("mcp_used") or bool(mcp_context)),
    }
