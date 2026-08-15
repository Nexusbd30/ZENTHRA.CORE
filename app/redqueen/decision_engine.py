from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from uuid import uuid4

from app.core.ai_provider import ai_provider
from app.core.mcp_context import evaluate_mcp_action_policy, normalize_mcp_context
from app.core.mcp_gateway import evaluate_mcp_tool_policy
from app.core.settings import settings
from app.core.signing import sign_payload
from app.identity.providers import is_identity_action_supported, strongest_supported_identity_action
from app.intelligence.llm_contract import normalize_llm_decision
from app.redqueen.analytical_brain import build_analytical_profile
from app.redqueen.anticipation import anticipate_attack_path
from app.redqueen.causal import build_causal_chain
from app.redqueen.mission import build_thinking_model
from app.redqueen.policy_matrix import evaluate_policy
from app.redqueen.prompts import TACTICAL_SYSTEM_PROMPT, tactical_user_prompt
from app.redqueen.xai import generate_xai_explanation
from app.secops.providers import is_devsecops_action_supported, strongest_supported_devsecops_action

ALLOWED_ACTIONS = {
    "observe",
    "soar_delegate",
    "require_mfa",
    "revoke_session",
    "degrade_privileges",
    "crypto_rotate",
    "require_release_approval",
    "revoke_pipeline_token",
    "quarantine_artifact",
    "block_deployment",
    "endpoint_isolate",
    "identity_lockdown",
    "network_isolate",
    "system_harden",
}

ACTION_SEVERITY = {
    "observe": 0,
    "soar_delegate": 1,
    "require_mfa": 1,
    "revoke_session": 2,
    "degrade_privileges": 2,
    "crypto_rotate": 2,
    "require_release_approval": 1,
    "revoke_pipeline_token": 2,
    "quarantine_artifact": 2,
    "block_deployment": 3,
    "endpoint_isolate": 2,
    "identity_lockdown": 3,
    "network_isolate": 4,
    "system_harden": 2,
}

DOMAIN_ACTIONS = {
    "identity": {
        "observe",
        "soar_delegate",
        "require_mfa",
        "revoke_session",
        "degrade_privileges",
        "identity_lockdown",
    },
    "endpoint": {"observe", "soar_delegate", "endpoint_isolate"},
    "network": {"observe", "soar_delegate", "network_isolate"},
    "crypto": {"observe", "soar_delegate", "crypto_rotate"},
    "devsecops": {
        "observe",
        "soar_delegate",
        "crypto_rotate",
        "require_release_approval",
        "revoke_pipeline_token",
        "quarantine_artifact",
        "block_deployment",
    },
    "generic": ALLOWED_ACTIONS,
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


def _action_domain(controls: dict) -> str:
    raw_perception = controls.get("perception")
    perception = raw_perception if isinstance(raw_perception, dict) else {}
    entity_type = str(perception.get("entity_type") or "").strip().lower()
    source = str(perception.get("source") or "").strip().lower()
    identity_contract = str(controls.get("identity_contract") or "").strip().lower()
    devsecops_contract = str(controls.get("devsecops_contract") or "").strip().lower()
    if identity_contract or entity_type == "user" or source.startswith("identity:"):
        return "identity"
    if (
        devsecops_contract
        or source.startswith("devsecops:")
        or source.startswith("secops:integration_security_abuse")
        or entity_type in {
            "repository",
            "pipeline",
            "artifact",
        }
    ):
        return "devsecops"
    if entity_type == "host":
        return "endpoint"
    if entity_type == "network":
        return "network"
    return "generic"


def _fallback_action(risk_score: float, *, domain: str = "generic") -> str:
    if domain == "identity":
        if risk_score >= 90:
            return "identity_lockdown"
        if risk_score >= 75:
            return "revoke_session"
        if risk_score >= 60:
            return "degrade_privileges"
        if risk_score >= 40:
            return "require_mfa"
        return "observe"
    if domain == "endpoint":
        if risk_score >= 65:
            return "endpoint_isolate"
        if risk_score >= 50:
            return "soar_delegate"
        return "observe"
    if domain == "network":
        if risk_score >= 85:
            return "network_isolate"
        if risk_score >= 50:
            return "soar_delegate"
        return "observe"
    if domain == "devsecops":
        if risk_score >= 90:
            return "block_deployment"
        if risk_score >= 80:
            return "quarantine_artifact"
        if risk_score >= 65:
            return "revoke_pipeline_token"
        if risk_score >= 55:
            return "crypto_rotate"
        if risk_score >= 45:
            return "require_release_approval"
        return "observe"
    if risk_score >= 90:
        return "network_isolate"
    if risk_score >= 75:
        return "identity_lockdown"
    if risk_score >= 65:
        return "endpoint_isolate"
    if risk_score >= 55:
        return "system_harden"
    if risk_score >= 50:
        return "soar_delegate"
    return "observe"


def _enforce_min_action_by_score(action: str, risk_score: float, *, domain: str = "generic") -> str:
    minimum = _fallback_action(risk_score, domain=domain)
    if ACTION_SEVERITY.get(action, 0) < ACTION_SEVERITY.get(minimum, 0):
        return minimum
    return action


def _llm_decide(target: str, risk_score: float, factors: list[str], *, domain: str) -> dict:
    raw = ai_provider.complete(
        TACTICAL_SYSTEM_PROMPT,
        tactical_user_prompt(target=target, risk_score=risk_score, factors=factors),
    )
    parsed = ai_provider.parse_json(raw)

    domain_actions = DOMAIN_ACTIONS.get(domain, DOMAIN_ACTIONS["generic"])
    minimum_action = _fallback_action(risk_score, domain=domain)
    return normalize_llm_decision(
        parsed,
        risk_score=risk_score,
        domain=domain,
        allowed_actions=ALLOWED_ACTIONS,
        domain_actions=domain_actions,
        fallback_action=minimum_action,
        minimum_action=minimum_action,
        action_severity=ACTION_SEVERITY,
        input_factors=factors,
    )


def _provider_adjusted_action(action: str, risk_score: float, *, domain: str, controls: dict) -> dict:
    if domain not in {"identity", "devsecops"} or action in {"observe", "soar_delegate"}:
        return {
            "action_type": action,
            "adjusted": False,
            "original_action_type": action,
            "reason": "",
        }

    if domain == "identity":
        provider = controls.get("identity_provider")
        if is_identity_action_supported(provider, action):
            return {
                "action_type": action,
                "adjusted": False,
                "original_action_type": action,
                "reason": "",
            }

        adjusted_action = strongest_supported_identity_action(provider, risk_score)
        return {
            "action_type": adjusted_action,
            "adjusted": adjusted_action != action,
            "original_action_type": action,
            "reason": f"identity_provider_capability_adjustment:{provider or 'custom'}",
        }

    provider = controls.get("devsecops_provider")
    if is_devsecops_action_supported(provider, action):
        return {
            "action_type": action,
            "adjusted": False,
            "original_action_type": action,
            "reason": "",
        }

    adjusted_action = strongest_supported_devsecops_action(provider, risk_score)
    return {
        "action_type": adjusted_action,
        "adjusted": adjusted_action != action,
        "original_action_type": action,
        "reason": f"devsecops_provider_capability_adjustment:{provider or 'custom'}",
    }


def generate_verdict(
    *,
    target: str,
    risk_score: float,
    factors: list[str],
    execution_controls: dict | None = None,
) -> dict:
    normalized_score = max(0.0, min(100.0, float(risk_score)))
    controls = execution_controls or {}
    action_domain = _action_domain(controls)

    ai_decision = _llm_decide(target, normalized_score, factors, domain=action_domain)
    provider_adjustment = _provider_adjusted_action(
        ai_decision["action_type"],
        normalized_score,
        domain=action_domain,
        controls=controls,
    )
    action_type = provider_adjustment["action_type"]
    confidence = ai_decision["confidence"]
    merged_factors = ai_decision["factors"]
    if provider_adjustment["adjusted"]:
        merged_factors = [
            *merged_factors,
            str(provider_adjustment["reason"]),
            f"provider_adjusted_from:{provider_adjustment['original_action_type']}",
            f"provider_adjusted_to:{action_type}",
        ]
    thinking_model = build_thinking_model(risk_score=normalized_score, action_type=action_type)
    merged_factors = list(
        dict.fromkeys(
            [
                *merged_factors,
                f"redqueen_posture:{thinking_model['posture']}",
                "redqueen_goal:control_intrusion_and_block_threats",
                "execution_boundary:ares_only",
            ]
        )
    )
    raw_mcp_context = controls.get("mcp_context") if isinstance(controls.get("mcp_context"), dict) else {}
    mcp_context = normalize_mcp_context(raw_mcp_context, target=target)
    mcp_action_policy = evaluate_mcp_action_policy(action_type, mcp_context)
    mcp_tool_policy = evaluate_mcp_tool_policy(mcp_context)
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
    analytical_profile = build_analytical_profile(
        target=target,
        risk_score=normalized_score,
        action_type=action_type,
        factors=merged_factors,
        controls={
            **controls,
            "mcp_context": mcp_context,
        },
    )
    attack_anticipation = anticipate_attack_path(
        target=target,
        risk_score=normalized_score,
        factors=merged_factors,
        controls={
            **controls,
            "mcp_context": mcp_context,
        },
    )
    merged_factors = list(
        dict.fromkeys(
            [
                *merged_factors,
                f"analytical_posture:{analytical_profile['posture']}",
                f"analytical_diligence:{analytical_profile['diligence_score']}",
                f"attack_horizon:{attack_anticipation['horizon']}",
                f"attack_stage:{attack_anticipation['latest_stage']}",
            ]
        )
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
            "policy_result": policy,
            "mcp_context": mcp_context,
            "mcp_action_policy": mcp_action_policy,
            "mcp_tool_policy": mcp_tool_policy,
            "llm_reasoning": ai_decision["reasoning"],
            "llm_contract": ai_decision["contract"],
            "llm_governance": ai_decision["governance"],
            "llm_action_accepted": ai_decision["llm_action_accepted"],
            "llm_final_action_source": ai_decision["final_action_source"],
            "llm_guardrail_decisions": ai_decision["guardrail_decisions"],
            "action_domain": ai_decision["domain"],
            "llm_requested_action_type": ai_decision["requested_action_type"],
            "provider_original_action_type": provider_adjustment["original_action_type"],
            "provider_action_adjusted": provider_adjustment["adjusted"],
            "provider_adjustment_reason": provider_adjustment["reason"],
            "minimum_action_type": ai_decision["minimum_action_type"],
            "minimum_action_enforced": ai_decision["minimum_action_enforced"],
            "redqueen_thinking_model": thinking_model,
            "redqueen_analytical_profile": analytical_profile,
            "redqueen_attack_anticipation": attack_anticipation,
        },
    )

    payload = asdict(verdict)
    payload["signature"] = sign_payload(payload)
    return payload
