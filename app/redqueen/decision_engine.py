from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from uuid import uuid4

from app.core.ai_provider import ai_provider
from app.core.settings import settings
from app.core.signing import sign_payload
from app.redqueen.causal import build_causal_chain
from app.redqueen.policy_matrix import evaluate_policy
from app.redqueen.prompts import TACTICAL_SYSTEM_PROMPT, tactical_user_prompt
from app.redqueen.xai import generate_xai_explanation

ALLOWED_ACTIONS = {
    "observe",
    "soar_delegate",
    "endpoint_isolate",
    "identity_lockdown",
    "network_isolate",
}

ACTION_SEVERITY = {
    "observe": 0,
    "soar_delegate": 1,
    "endpoint_isolate": 2,
    "identity_lockdown": 3,
    "network_isolate": 4,
}


@dataclass
class VerdictDraft:
    verdict_id: str
    timestamp: str
    target: str
    action_type: str
    confidence: float
    risk_score: float
    factors: list[str]
    policy_check: bool
    requires_human: bool
    justification_xai: str
    causal_chain: dict = field(default_factory=dict)
    execution_controls: dict = field(default_factory=dict)


def _fallback_action(risk_score: float) -> str:
    if risk_score >= 90:
        return "network_isolate"
    if risk_score >= 75:
        return "identity_lockdown"
    if risk_score >= 65:
        return "endpoint_isolate"
    if risk_score >= 50:
        return "soar_delegate"
    return "observe"


def _enforce_min_action_by_score(action: str, risk_score: float) -> str:
    minimum = _fallback_action(risk_score)
    if ACTION_SEVERITY.get(action, 0) < ACTION_SEVERITY.get(minimum, 0):
        return minimum
    return action


def _llm_decide(target: str, risk_score: float, factors: list[str]) -> dict:
    raw = ai_provider.complete(
        TACTICAL_SYSTEM_PROMPT,
        tactical_user_prompt(target=target, risk_score=risk_score, factors=factors),
    )
    parsed = ai_provider.parse_json(raw)

    requested_action = str(parsed.get("action_type", "")).strip().lower()
    action = requested_action
    if action not in ALLOWED_ACTIONS:
        action = _fallback_action(risk_score)
    action = _enforce_min_action_by_score(action, risk_score)

    try:
        confidence = float(parsed.get("confidence", risk_score / 100.0))
    except (TypeError, ValueError):
        confidence = risk_score / 100.0

    confidence = max(0.5, min(0.99, confidence))

    llm_factors = parsed.get("factors")
    if not isinstance(llm_factors, list):
        llm_factors = []

    merged_factors = list(dict.fromkeys([*factors, *[str(f) for f in llm_factors if f]]))
    if not merged_factors:
        merged_factors = ["baseline_risk_assessment"]

    return {
        "action_type": action,
        "requested_action_type": requested_action or "unavailable",
        "confidence": confidence,
        "factors": merged_factors,
        "reasoning": str(parsed.get("reasoning", "llm_reasoning_unavailable")),
        "minimum_action_type": _fallback_action(risk_score),
        "minimum_action_enforced": action != requested_action,
    }


def generate_verdict(
    *,
    target: str,
    risk_score: float,
    factors: list[str],
    execution_controls: dict | None = None,
) -> dict:
    normalized_score = max(0.0, min(100.0, float(risk_score)))

    ai_decision = _llm_decide(target, normalized_score, factors)
    action_type = ai_decision["action_type"]
    confidence = ai_decision["confidence"]
    merged_factors = ai_decision["factors"]
    controls = execution_controls or {}
    perception = controls.get("perception") if isinstance(controls.get("perception"), dict) else {}

    policy = evaluate_policy(score=normalized_score, action_type=action_type)
    requires_human = bool(policy.get("requires_human")) or (
        normalized_score >= settings.REDQUEEN_HUMAN_APPROVAL_SCORE
    )
    causal_chain = build_causal_chain(
        target=target,
        risk_score=normalized_score,
        action_type=action_type,
        perception=perception,
        factors=merged_factors,
        llm_reasoning=ai_decision["reasoning"],
    )

    verdict = VerdictDraft(
        verdict_id=uuid4().hex,
        timestamp=datetime.now(UTC).isoformat(),
        target=target,
        action_type=action_type,
        confidence=confidence,
        risk_score=normalized_score,
        factors=merged_factors,
        policy_check=bool(policy.get("allowed", False)),
        requires_human=requires_human,
        justification_xai=generate_xai_explanation(
            target=target,
            risk_score=normalized_score,
            action_type=action_type,
            confidence=confidence,
            factors=merged_factors,
            requires_human=requires_human,
            causal_chain=causal_chain,
        ),
        causal_chain=causal_chain,
        execution_controls={
            **controls,
            "llm_reasoning": ai_decision["reasoning"],
            "llm_requested_action_type": ai_decision["requested_action_type"],
            "minimum_action_type": ai_decision["minimum_action_type"],
            "minimum_action_enforced": ai_decision["minimum_action_enforced"],
        },
    )

    payload = asdict(verdict)
    payload["signature"] = sign_payload(payload)
    return payload
