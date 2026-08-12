from __future__ import annotations

from typing import Any

from app.core.settings import settings

LLM_GOVERNANCE_SCHEMA = "vaelqorix.llm_governance.v1"
LLM_DECISION_TRACE_SCHEMA = "vaelqorix.llm_decision_trace.v1"

REQUIRED_LLM_CONTRACT_FIELDS: tuple[str, ...] = (
    "schema",
    "domain",
    "requested_action_type",
    "action_type",
    "fallback_action_type",
    "minimum_action_type",
    "final_action_source",
    "guardrail_decisions",
    "confidence",
    "reasoning",
)

REQUIRED_GUARDRAILS: tuple[str, ...] = (
    "allowed_action_validation",
    "domain_action_validation",
    "minimum_action_enforcement",
    "confidence_clamping",
)


def assess_llm_contract(contract: dict[str, Any]) -> dict[str, Any]:
    missing_fields = [
        field for field in REQUIRED_LLM_CONTRACT_FIELDS if field not in contract
    ]
    guardrail_decisions = contract.get("guardrail_decisions")
    if not isinstance(guardrail_decisions, list):
        guardrail_decisions = []
    present_guardrails = {
        str(decision.get("guardrail"))
        for decision in guardrail_decisions
        if isinstance(decision, dict)
    }
    confidence = contract.get("confidence")
    confidence_valid = isinstance(confidence, (int, float)) and 0.5 <= float(confidence) <= 0.99
    schema_valid = contract.get("schema") == "redqueen.llm_decision.v1"
    final_action_source = str(contract.get("final_action_source") or "")
    source_valid = final_action_source in {"llm", "guardrail"}
    missing_guardrails = []
    if not (
        present_guardrails
        & {"action_validation", "allowed_action_validation", "domain_action_validation"}
    ):
        missing_guardrails.append("action_validation")
    if "minimum_action_enforcement" not in present_guardrails:
        missing_guardrails.append("minimum_action_enforcement")
    approved = (
        schema_valid
        and source_valid
        and confidence_valid
        and not missing_fields
        and not missing_guardrails
    )
    return {
        "schema": LLM_GOVERNANCE_SCHEMA,
        "decision_trace_schema": LLM_DECISION_TRACE_SCHEMA,
        "approved_for_ares": approved,
        "schema_valid": schema_valid,
        "source_valid": source_valid,
        "confidence_valid": confidence_valid,
        "missing_fields": missing_fields,
        "missing_guardrails": missing_guardrails,
        "required_guardrails": list(REQUIRED_GUARDRAILS),
        "present_guardrails": sorted(present_guardrails),
    }


def build_llm_governance_status() -> dict[str, Any]:
    provider = str(getattr(settings, "AI_PROVIDER", "local_stub") or "local_stub").lower()
    return {
        "schema": LLM_GOVERNANCE_SCHEMA,
        "decision_trace_schema": LLM_DECISION_TRACE_SCHEMA,
        "provider": provider,
        "model": settings.AI_MODEL,
        "real_mode": provider not in {"local_stub", "stub", "mock"},
        "contract_required": True,
        "ares_execution_requires_approved_contract": True,
        "fallback_allowed": True,
        "fallback_provider": "local_stub",
        "required_contract_fields": list(REQUIRED_LLM_CONTRACT_FIELDS),
        "required_guardrails": list(REQUIRED_GUARDRAILS),
        "evidence_required": [
            "llm_contract",
            "llm_governance",
            "guardrail_decisions",
            "mcp_action_policy",
            "mcp_tool_policy",
        ],
    }
