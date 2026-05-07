from __future__ import annotations

from dataclasses import dataclass

from app.ares.kill_switch import kill_switch_state
from app.ares.planner import DISRUPTIVE_ACTIONS
from app.core.mcp_context import evaluate_mcp_action_policy, normalize_mcp_context
from app.core.signing import verify_payload_signature
from app.redqueen.policy_matrix import evaluate_policy


@dataclass
class ValidationResult:
    valid: bool
    code: str
    detail: str


def validate_verdict(verdict: dict) -> ValidationResult:
    ks = kill_switch_state()
    if not ks.get("ares_enabled", True):
        return ValidationResult(False, "kill_switch", "ARES is disabled by kill-switch")

    signature = verdict.get("signature")
    if not isinstance(signature, str) or not signature:
        return ValidationResult(False, "signature_missing", "Verdict signature is required")

    to_verify = {k: v for k, v in verdict.items() if k != "signature"}
    if not verify_payload_signature(to_verify, signature):
        return ValidationResult(False, "signature_invalid", "Verdict signature is invalid")

    risk_score = float(verdict.get("risk_score", 0.0))
    action_type = str(verdict.get("action_type", "observe"))
    policy = evaluate_policy(score=risk_score, action_type=action_type)

    if not policy.get("allowed", False):
        return ValidationResult(False, "policy_denied", "Policy matrix denied action")

    controls = verdict.get("execution_controls")
    controls = controls if isinstance(controls, dict) else {}
    raw_mcp_context = controls.get("mcp_context") if isinstance(controls.get("mcp_context"), dict) else {}
    mcp_context = normalize_mcp_context(raw_mcp_context, target=str(verdict.get("target") or ""))
    mcp_policy = evaluate_mcp_action_policy(action_type, mcp_context)
    if not mcp_policy.get("allowed", False):
        return ValidationResult(
            False,
            str(mcp_policy.get("code") or "mcp_action_denied"),
            str(mcp_policy.get("detail") or "MCP action policy denied action"),
        )

    dry_run = bool(controls.get("dry_run", False))
    if action_type in DISRUPTIVE_ACTIONS and not dry_run:
        if not controls.get("threat_id") and not controls.get("change_ticket"):
            return ValidationResult(
                False,
                "execution_control_missing",
                "Disruptive action requires threat_id or change_ticket control",
            )

    return ValidationResult(True, "ok", "validated")
