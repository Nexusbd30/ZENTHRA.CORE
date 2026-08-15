from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.ares.planner import DISRUPTIVE_ACTIONS


@dataclass(frozen=True)
class FirewallDecision:
    allowed: bool
    code: str
    detail: str
    severity: str = "low"
    evidence: dict[str, Any] = field(default_factory=dict)


def _policy_list(policy: dict[str, Any], key: str) -> set[str]:
    raw = policy.get(key)
    if not isinstance(raw, list):
        return set()
    return {str(item).strip().lower() for item in raw if str(item).strip()}


def _target_matches(target: str, protected_targets: set[str]) -> bool:
    normalized = target.strip().lower()
    return normalized in protected_targets or any(
        item.endswith("*") and normalized.startswith(item[:-1]) for item in protected_targets
    )


def evaluate_internal_firewall(
    *,
    verdict: dict[str, Any],
    plan: dict[str, Any],
    advisor_review: dict[str, Any],
    controls: dict[str, Any] | None = None,
) -> FirewallDecision:
    controls = controls if isinstance(controls, dict) else {}
    action_type = str(plan.get("action_type") or verdict.get("action_type") or "observe").lower()
    target = str(plan.get("target") or verdict.get("target") or "").strip()
    raw_policy = controls.get("firewall_policy")
    policy: dict[str, Any] = raw_policy if isinstance(raw_policy, dict) else {}
    deny_actions = _policy_list(policy, "deny_actions")
    protected_targets = _policy_list(policy, "protected_targets")
    allowed_actions = _policy_list(policy, "allowed_actions")

    mcp_action_policy = advisor_review.get("mcp_action_policy")
    if isinstance(mcp_action_policy, dict) and not mcp_action_policy.get("allowed", True):
        return FirewallDecision(
            False,
            str(mcp_action_policy.get("code") or "mcp_action_denied"),
            str(mcp_action_policy.get("detail") or "MCP action policy denied action"),
            severity="high",
            evidence={"mcp_action_policy": mcp_action_policy},
        )

    mcp_tool_policy = verdict.get("execution_controls", {}).get("mcp_tool_policy", {})
    if isinstance(mcp_tool_policy, dict) and not mcp_tool_policy.get("allowed", True):
        return FirewallDecision(
            False,
            str(mcp_tool_policy.get("code") or "mcp_tool_denied"),
            str(mcp_tool_policy.get("detail") or "MCP tool policy denied context"),
            severity="high",
            evidence={"mcp_tool_policy": mcp_tool_policy},
        )

    if action_type in deny_actions:
        return FirewallDecision(
            False,
            "firewall_action_denied",
            f"ARES internal firewall denied action '{action_type}'",
            severity="critical",
            evidence={"deny_actions": sorted(deny_actions)},
        )

    if allowed_actions and action_type not in allowed_actions:
        return FirewallDecision(
            False,
            "firewall_action_not_allowed",
            f"ARES internal firewall allowlist does not include action '{action_type}'",
            severity="high",
            evidence={"allowed_actions": sorted(allowed_actions)},
        )

    if _target_matches(target, protected_targets) and action_type in DISRUPTIVE_ACTIONS:
        if not controls.get("change_ticket") or not controls.get("dependency_owner_approved"):
            return FirewallDecision(
                False,
                "firewall_protected_target_control_missing",
                "Protected target requires change_ticket and dependency_owner_approved",
                severity="critical",
                evidence={"target": target, "protected_targets": sorted(protected_targets)},
            )

    if (
        advisor_review.get("safe_to_execute") is False
        and controls.get("enforce_advisor_firewall") is True
        and not controls.get("dry_run")
    ):
        return FirewallDecision(
            False,
            "advisor_marked_unsafe",
            "ARES advisor marked the plan unsafe and firewall enforcement is enabled",
            severity="high",
            evidence={"advisor_review": advisor_review},
        )

    return FirewallDecision(
        True,
        "ok",
        "ARES internal firewall allowed execution",
        severity="low",
        evidence={
            "action_type": action_type,
            "target": target,
            "protected_target": _target_matches(target, protected_targets),
        },
    )
