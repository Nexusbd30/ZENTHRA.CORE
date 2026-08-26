from __future__ import annotations

from typing import Any

from app.intelligence.governance import assess_llm_contract

LLM_DECISION_SCHEMA = "redqueen.llm_decision.v1"


def normalize_llm_decision(
    parsed: dict[str, Any],
    *,
    risk_score: float,
    domain: str,
    allowed_actions: set[str],
    domain_actions: set[str],
    fallback_action: str,
    minimum_action: str,
    action_severity: dict[str, int],
    input_factors: list[str],
) -> dict[str, Any]:
    requested_action = str(parsed.get("action_type", "")).strip().lower()
    action = requested_action
    fallback_reason = ""
    guardrail_decisions: list[dict[str, Any]] = []
    if action not in allowed_actions:
        action = fallback_action
        fallback_reason = "action_not_allowed"
        guardrail_decisions.append(
            {
                "guardrail": "allowed_action_validation",
                "result": "fallback_applied",
                "from_action": requested_action or "unavailable",
                "to_action": fallback_action,
                "reason": fallback_reason,
            }
        )
    elif action not in domain_actions:
        action = fallback_action
        fallback_reason = "action_outside_domain"
        guardrail_decisions.append(
            {
                "guardrail": "domain_action_validation",
                "result": "fallback_applied",
                "from_action": requested_action,
                "to_action": fallback_action,
                "reason": fallback_reason,
            }
        )
    else:
        guardrail_decisions.append(
            {
                "guardrail": "action_validation",
                "result": "accepted",
                "from_action": action or "unavailable",
                "to_action": action or "unavailable",
                "reason": "",
            }
        )

    minimum_enforced = False
    if action_severity.get(action, 0) < action_severity.get(minimum_action, 0):
        original_action = action
        action = minimum_action
        minimum_enforced = True
        guardrail_decisions.append(
            {
                "guardrail": "minimum_action_enforcement",
                "result": "minimum_applied",
                "from_action": original_action or "unavailable",
                "to_action": minimum_action,
                "reason": "risk_score_requires_stronger_action",
            }
        )
    else:
        guardrail_decisions.append(
            {
                "guardrail": "minimum_action_enforcement",
                "result": "not_required",
                "from_action": action or "unavailable",
                "to_action": action or "unavailable",
                "reason": "",
            }
        )

    try:
        confidence = float(parsed.get("confidence", risk_score / 100.0))
    except (TypeError, ValueError):
        confidence = risk_score / 100.0
    confidence = max(0.5, min(0.99, confidence))

    llm_factors = parsed.get("factors")
    if not isinstance(llm_factors, list):
        llm_factors = []
    merged_factors = list(dict.fromkeys([*input_factors, *[str(f) for f in llm_factors if f]]))
    if not merged_factors:
        merged_factors = ["baseline_risk_assessment"]

    contract = {
        "schema": LLM_DECISION_SCHEMA,
        "domain": domain,
        "requested_action_type": requested_action or "unavailable",
        "action_type": action,
        "fallback_action_type": fallback_action,
        "fallback_reason": fallback_reason,
        "minimum_action_type": minimum_action,
        "minimum_action_enforced": minimum_enforced,
        "llm_action_accepted": not fallback_reason and not minimum_enforced,
        "final_action_source": "llm" if not fallback_reason and not minimum_enforced else "guardrail",
        "guardrail_decisions": guardrail_decisions,
        "confidence": confidence,
        "reasoning": str(parsed.get("reasoning", "llm_reasoning_unavailable")),
        "factor_count": len(merged_factors),
    }
    governance = assess_llm_contract(contract)
    return {
        **contract,
        "governance": governance,
        "factors": merged_factors,
        "contract": contract,
    }
