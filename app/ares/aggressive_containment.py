from __future__ import annotations

from typing import Any

CONTAINMENT_SCHEMA = "vaelqorix.ares.aggressive_containment.v1"


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _block_steps(bridge_trace: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    raw_blocks = bridge_trace.get("block_targets")
    blocks = raw_blocks if isinstance(raw_blocks, list) else []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        block_type = str(block.get("type") or "")
        action = str(block.get("action") or "")
        value = str(block.get("value") or "")
        if not value:
            continue
        if block_type == "network_indicator":
            control = "perimeter_block"
        elif block_type in {"identity", "session"}:
            control = "identity_revocation"
        elif block_type in {"device", "runner"}:
            control = "endpoint_isolation"
        elif block_type in {"repository", "pipeline"}:
            control = "release_freeze"
        else:
            control = "soc_review"
        steps.append(
            {
                "control": control,
                "target": value,
                "source": block_type,
                "action": action,
                "requires_confirmation": control in {"perimeter_block", "endpoint_isolation", "release_freeze"},
            }
        )
    return steps


def build_aggressive_containment(
    *,
    verdict: dict[str, Any],
    bridge_trace: dict[str, Any] | None = None,
    controls: dict[str, Any] | None = None,
) -> dict[str, Any]:
    controls = controls if isinstance(controls, dict) else {}
    bridge_trace = bridge_trace if isinstance(bridge_trace, dict) else {}
    risk_score = max(0.0, min(100.0, float(verdict.get("risk_score") or 0.0)))
    action_type = str(verdict.get("action_type") or "observe")
    target = str(verdict.get("target") or "")
    neutralization_steps = [
        {
            "control": "preserve_bridge_evidence",
            "target": target,
            "source": "ares",
            "action": "snapshot_trace_context",
            "requires_confirmation": False,
        },
        *_block_steps(bridge_trace),
        {
            "control": "open_traceability_case",
            "target": target,
            "source": "soc",
            "action": "create_case_with_chain_of_custody",
            "requires_confirmation": False,
        },
    ]
    if action_type in {"network_isolate", "identity_lockdown", "endpoint_isolate", "aggressive_containment"}:
        neutralization_steps.append(
            {
                "control": "verify_intruder_neutralized",
                "target": target,
                "source": "ares",
                "action": "confirm_no_active_session_or_path",
                "requires_confirmation": False,
            }
        )
    if controls.get("change_ticket"):
        guardrails = ["change_ticket_present"]
    else:
        guardrails = ["change_ticket_required_for_live_execution"]
    guardrails.extend(
        [
            "kill_switch_enforced",
            "ares_internal_firewall_enforced",
            "human_approval_for_disruptive_controls",
            "no_external_counter_intrusion",
        ]
    )

    return {
        "schema": CONTAINMENT_SCHEMA,
        "mode": "authorized_active_defense",
        "target": target,
        "risk_score": risk_score,
        "activation": "immediate" if risk_score >= 85 else "operator_gated",
        "external_action_policy": "block_and_report_only",
        "allowed_scope": [
            "owned_identity_tenant",
            "owned_network_perimeter",
            "owned_endpoint_fleet",
            "owned_devsecops_platform",
            "soc_case_management",
        ],
        "neutralization_steps": neutralization_steps,
        "guardrails": list(dict.fromkeys(guardrails)),
        "bridge_trace": bridge_trace,
    }
