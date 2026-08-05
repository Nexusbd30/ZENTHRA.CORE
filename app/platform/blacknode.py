from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.ares.kill_switch import kill_switch_state
from app.ares.planner import DISRUPTIVE_ACTIONS
from app.core.mcp_context import evaluate_mcp_action_policy, normalize_mcp_context
from app.core.mcp_gateway import evaluate_mcp_tool_policy
from app.core.signing import verify_payload_signature
from app.identity.providers import IDENTITY_ACTION_REQUIRED_COMMANDS, validate_identity_action
from app.redqueen.policy_matrix import evaluate_policy
from app.secops.providers import DEVSECOPS_ACTION_REQUIRED_COMMANDS, validate_devsecops_action

READ_ONLY_ACTIONS = {"observe"}
ANALYSIS_ACTIONS = {"soar_delegate"}
DRAFTING_ACTIONS = {"require_release_approval"}
APPROVAL_REQUIRED_ACTIONS = {
    "require_mfa",
    "revoke_session",
    "degrade_privileges",
    "crypto_rotate",
    "revoke_pipeline_token",
    "quarantine_artifact",
    "block_deployment",
    "endpoint_isolate",
    "identity_lockdown",
    "network_isolate",
}
DESTRUCTIVE_ACTIONS: set[str] = set()


@dataclass(frozen=True)
class BlackNodeDecision:
    allowed: bool
    code: str
    detail: str
    risk_level: str = "low"
    evidence: dict[str, Any] = field(default_factory=dict)


def classify_action_risk(action_type: str, risk_score: float = 0.0) -> str:
    action = str(action_type or "observe").strip().lower()
    score = float(risk_score or 0.0)
    if action in DESTRUCTIVE_ACTIONS:
        return "destructive"
    if action in APPROVAL_REQUIRED_ACTIONS or action in DISRUPTIVE_ACTIONS or score >= 80:
        return "approval_required"
    if action in DRAFTING_ACTIONS or score >= 55:
        return "drafting"
    if action in ANALYSIS_ACTIONS or score >= 35:
        return "analysis"
    return "read_only"


class BlackNodeSecurityGateway:
    name = "BlackNode"
    contract = "nexusops.blacknode.security_gateway.v1"

    def build_status(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "contract": self.contract,
            "controls": [
                "signature_validation",
                "kill_switch",
                "policy_matrix",
                "mcp_action_policy",
                "mcp_tool_policy",
                "provider_capability_validation",
                "disruptive_action_controls",
            ],
            "mvp_allowed_tool_levels": ["read_only", "analysis", "drafting"],
            "approval_required_levels": ["approval_required"],
            "blocked_tool_levels": ["destructive"],
        }

    def validate_verdict(self, verdict: dict[str, Any]) -> BlackNodeDecision:
        ks = kill_switch_state()
        if not ks.get("ares_enabled", True):
            return BlackNodeDecision(False, "kill_switch", "ARES is disabled by kill-switch")

        signature = verdict.get("signature")
        if not isinstance(signature, str) or not signature:
            return BlackNodeDecision(False, "signature_missing", "Verdict signature is required")

        to_verify = {k: v for k, v in verdict.items() if k != "signature"}
        if not verify_payload_signature(to_verify, signature):
            return BlackNodeDecision(False, "signature_invalid", "Verdict signature is invalid")

        risk_score = float(verdict.get("risk_score", 0.0))
        action_type = str(verdict.get("action_type", "observe"))
        action_risk = classify_action_risk(action_type, risk_score)
        policy = evaluate_policy(score=risk_score, action_type=action_type)

        if not policy.get("allowed", False):
            return BlackNodeDecision(
                False,
                "policy_denied",
                "Policy matrix denied action",
                risk_level=action_risk,
                evidence={"policy": policy},
            )

        controls = verdict.get("execution_controls")
        controls = controls if isinstance(controls, dict) else {}
        raw_mcp_context = (
            controls.get("mcp_context") if isinstance(controls.get("mcp_context"), dict) else {}
        )
        mcp_context = normalize_mcp_context(
            raw_mcp_context,
            target=str(verdict.get("target") or ""),
        )
        mcp_policy = evaluate_mcp_action_policy(action_type, mcp_context)
        if not mcp_policy.get("allowed", False):
            return BlackNodeDecision(
                False,
                str(mcp_policy.get("code") or "mcp_action_denied"),
                str(mcp_policy.get("detail") or "MCP action policy denied action"),
                risk_level=action_risk,
                evidence={"mcp_action_policy": mcp_policy},
            )

        mcp_tool_policy = evaluate_mcp_tool_policy(mcp_context)
        if not mcp_tool_policy.get("allowed", False):
            return BlackNodeDecision(
                False,
                str(mcp_tool_policy.get("code") or "mcp_tool_denied"),
                str(mcp_tool_policy.get("detail") or "MCP tool policy denied context"),
                risk_level=action_risk,
                evidence={"mcp_tool_policy": mcp_tool_policy},
            )

        if action_type in IDENTITY_ACTION_REQUIRED_COMMANDS:
            try:
                validate_identity_action(controls.get("identity_provider"), action_type)
            except ValueError as exc:
                return BlackNodeDecision(
                    False,
                    "identity_provider_unsupported_action",
                    str(exc),
                    risk_level=action_risk,
                )

        if action_type in DEVSECOPS_ACTION_REQUIRED_COMMANDS:
            try:
                validate_devsecops_action(controls.get("devsecops_provider"), action_type)
            except ValueError as exc:
                return BlackNodeDecision(
                    False,
                    "devsecops_provider_unsupported_action",
                    str(exc),
                    risk_level=action_risk,
                )

        dry_run = bool(controls.get("dry_run", False))
        if action_type in DISRUPTIVE_ACTIONS and not dry_run:
            if not controls.get("threat_id") and not controls.get("change_ticket"):
                return BlackNodeDecision(
                    False,
                    "execution_control_missing",
                    "Disruptive action requires threat_id or change_ticket control",
                    risk_level=action_risk,
                )

        return BlackNodeDecision(
            True,
            "ok",
            "validated",
            risk_level=action_risk,
            evidence={
                "policy": policy,
                "mcp_action_policy": mcp_policy,
                "mcp_tool_policy": mcp_tool_policy,
            },
        )


blacknode_gateway = BlackNodeSecurityGateway()

