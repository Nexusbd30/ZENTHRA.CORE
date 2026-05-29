from __future__ import annotations

from typing import Any

DISRUPTIVE_ACTIONS = {
    "network_isolate",
    "identity_lockdown",
    "endpoint_isolate",
    "crypto_rotate",
    "revoke_session",
    "degrade_privileges",
    "revoke_pipeline_token",
    "quarantine_artifact",
    "block_deployment",
}


def _step(
    name: str,
    *,
    target: str,
    impact: str,
    rollback: str | None,
    criticality: int,
    requires_confirmation: bool = False,
) -> dict:
    return {
        "step": name,
        "payload": {"target": target},
        "impact": impact,
        "rollback": rollback,
        "criticality": criticality,
        "requires_confirmation": requires_confirmation,
    }


def build_plan(verdict: dict) -> dict:
    action_type = verdict.get("action_type", "observe")
    target = verdict.get("target", "unknown")
    risk_score = float(verdict.get("risk_score", 0.0) or 0.0)
    raw_causal_chain = verdict.get("causal_chain")
    causal_chain: dict[str, Any] = raw_causal_chain if isinstance(raw_causal_chain, dict) else {}

    steps: list[dict] = []
    if action_type == "network_isolate":
        steps = [
            _step(
                "resolve_target",
                target=target,
                impact="asset inventory lookup only",
                rollback=None,
                criticality=1,
            ),
            _step(
                "isolate_network",
                target=target,
                impact="blocks network access for the target asset",
                rollback="network_rollback",
                criticality=5,
                requires_confirmation=True,
            ),
            _step(
                "confirm_isolation",
                target=target,
                impact="verifies containment state",
                rollback=None,
                criticality=2,
            ),
        ]
    elif action_type == "identity_lockdown":
        steps = [
            _step(
                "resolve_identity",
                target=target,
                impact="identity lookup only",
                rollback=None,
                criticality=1,
            ),
            _step(
                "disable_credentials",
                target=target,
                impact="prevents authentication for the target identity",
                rollback="identity_rollback",
                criticality=4,
                requires_confirmation=True,
            ),
            _step(
                "force_mfa",
                target=target,
                impact="forces re-authentication and MFA reset",
                rollback="identity_rollback",
                criticality=3,
            ),
        ]
    elif action_type == "require_mfa":
        steps = [
            _step(
                "resolve_identity",
                target=target,
                impact="identity lookup only",
                rollback=None,
                criticality=1,
            ),
            _step(
                "require_mfa",
                target=target,
                impact="requires strong re-authentication for the target identity",
                rollback=None,
                criticality=2,
            ),
        ]
    elif action_type == "revoke_session":
        steps = [
            _step(
                "resolve_identity",
                target=target,
                impact="identity lookup only",
                rollback=None,
                criticality=1,
            ),
            _step(
                "revoke_sessions",
                target=target,
                impact="invalidates active sessions and refresh tokens",
                rollback=None,
                criticality=3,
            ),
        ]
    elif action_type == "degrade_privileges":
        steps = [
            _step(
                "resolve_identity",
                target=target,
                impact="identity lookup only",
                rollback=None,
                criticality=1,
            ),
            _step(
                "degrade_privileges",
                target=target,
                impact="temporarily removes elevated privileges from the target identity",
                rollback="identity_rollback",
                criticality=3,
                requires_confirmation=True,
            ),
        ]
    elif action_type == "endpoint_isolate":
        steps = [
            _step(
                "resolve_endpoint",
                target=target,
                impact="endpoint lookup only",
                rollback=None,
                criticality=1,
            ),
            _step(
                "isolate_endpoint",
                target=target,
                impact="contains endpoint communications",
                rollback="endpoint_rollback",
                criticality=4,
                requires_confirmation=True,
            ),
            _step(
                "snapshot_forensics",
                target=target,
                impact="collects volatile forensic evidence",
                rollback=None,
                criticality=2,
            ),
        ]
    elif action_type == "soar_delegate":
        steps = [
            _step(
                "open_ticket",
                target=target,
                impact="creates SOC case",
                rollback=None,
                criticality=1,
            ),
            _step(
                "notify_soc",
                target=target,
                impact="notifies operators",
                rollback=None,
                criticality=1,
            ),
        ]
    elif action_type == "crypto_rotate":
        steps = [
            _step(
                "resolve_crypto_material",
                target=target,
                impact="KMS or vault lookup only",
                rollback=None,
                criticality=1,
            ),
            _step(
                "rotate_crypto_material",
                target=target,
                impact="rotates affected key or secret material",
                rollback="crypto_rotation_rollback",
                criticality=4,
                requires_confirmation=True,
            ),
            _step(
                "verify_rotation",
                target=target,
                impact="verifies consumers can use the new material",
                rollback=None,
                criticality=2,
            ),
        ]
    elif action_type == "require_release_approval":
        steps = [
            _step(
                "resolve_pipeline",
                target=target,
                impact="pipeline lookup only",
                rollback=None,
                criticality=1,
            ),
            _step(
                "require_release_approval",
                target=target,
                impact="requires release owner or SecOps approval before deployment",
                rollback="devsecops_rollback",
                criticality=2,
            ),
            _step(
                "notify_release_owner",
                target=target,
                impact="notifies release owner and SecOps queue",
                rollback=None,
                criticality=1,
            ),
        ]
    elif action_type == "revoke_pipeline_token":
        steps = [
            _step(
                "resolve_pipeline",
                target=target,
                impact="pipeline lookup only",
                rollback=None,
                criticality=1,
            ),
            _step(
                "revoke_pipeline_token",
                target=target,
                impact="invalidates suspected CI/CD token or runner credential",
                rollback=None,
                criticality=3,
            ),
        ]
    elif action_type == "quarantine_artifact":
        steps = [
            _step(
                "resolve_pipeline",
                target=target,
                impact="pipeline and artifact lookup only",
                rollback=None,
                criticality=1,
            ),
            _step(
                "quarantine_artifact",
                target=target,
                impact="marks build artifact as not deployable",
                rollback="devsecops_rollback",
                criticality=4,
                requires_confirmation=True,
            ),
            _step(
                "notify_release_owner",
                target=target,
                impact="notifies release owner and SecOps queue",
                rollback=None,
                criticality=1,
            ),
        ]
    elif action_type == "block_deployment":
        steps = [
            _step(
                "resolve_pipeline",
                target=target,
                impact="pipeline and deployment target lookup only",
                rollback=None,
                criticality=1,
            ),
            _step(
                "block_deployment",
                target=target,
                impact="blocks deployment until security approval or rollback",
                rollback="devsecops_rollback",
                criticality=4,
                requires_confirmation=True,
            ),
            _step(
                "notify_release_owner",
                target=target,
                impact="notifies release owner and SecOps queue",
                rollback=None,
                criticality=1,
            ),
        ]
    else:
        steps = [
            _step(
                "observe_only",
                target=target,
                impact="no operational change",
                rollback=None,
                criticality=0,
            )
        ]

    max_criticality = max((int(step.get("criticality", 0)) for step in steps), default=0)
    return {
        "action_type": action_type,
        "target": target,
        "risk_score": risk_score,
        "requires_confirmation": any(bool(step.get("requires_confirmation")) for step in steps),
        "max_criticality": max_criticality,
        "rollback_strategy": "transactional_reverse_order" if action_type in DISRUPTIVE_ACTIONS else "none",
        "causal_summary": causal_chain.get("action_rationale", ""),
        "steps": steps,
    }
