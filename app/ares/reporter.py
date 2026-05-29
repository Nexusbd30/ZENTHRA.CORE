from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime


def _intelligence_trace(verdict: dict) -> dict:
    controls = verdict.get("execution_controls", {})
    if not isinstance(controls, dict):
        controls = {}
    return {
        "kind": "intelligence_trace",
        "action_domain": controls.get("action_domain", ""),
        "policy_rule": verdict.get("policy_rule", ""),
        "rag_references": controls.get("rag_references", []),
        "mcp_context": controls.get("mcp_context", {}),
        "mcp_action_policy": controls.get("mcp_action_policy", {}),
        "mcp_tool_policy": controls.get("mcp_tool_policy", {}),
        "llm_contract": controls.get("llm_contract", {}),
        "llm_final_action_source": controls.get("llm_final_action_source", ""),
        "llm_guardrail_decisions": controls.get("llm_guardrail_decisions", []),
        "provider_action_adjusted": controls.get("provider_action_adjusted", False),
        "provider_original_action_type": controls.get("provider_original_action_type", ""),
        "provider_adjustment_reason": controls.get("provider_adjustment_reason", ""),
        "decision_factors": verdict.get("factors", []),
    }


def build_execution_result(*, verdict: dict, execution: dict, actor: str = "ares") -> dict:
    executed_steps = execution.get("executed_steps", [])
    rollback_events = execution.get("rollback_events", [])
    status = execution.get("status", "unknown")
    reward = 0.0
    if status == "success":
        reward += 1.0
    elif status == "failed":
        reward -= 0.3
    if rollback_events:
        reward -= 0.4

    evidence = [*executed_steps, _intelligence_trace(verdict)]
    record = {
        "verdict_id": verdict.get("verdict_id"),
        "ares_id": actor,
        "action_type": verdict.get("action_type", ""),
        "target_entity": verdict.get("target", ""),
        "target_system": verdict.get("execution_controls", {}).get("target_system", ""),
        "status": status,
        "duration_ms": execution.get("duration_ms", 0),
        "pre_state": execution.get("pre_state", {}),
        "post_state": execution.get("post_state", {}),
        "evidence": evidence,
        "rollback_payload": {"rollback_events": rollback_events},
        "rl_reward": round(reward, 2),
        "error_code": "" if status == "success" else "execution_failed",
        "timestamp": datetime.now(UTC).isoformat(),
    }

    normalized = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    record["result_hash"] = hashlib.sha256(normalized).hexdigest()
    return record
