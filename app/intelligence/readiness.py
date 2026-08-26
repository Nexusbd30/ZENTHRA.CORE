from __future__ import annotations

from typing import Any

from app.intelligence.repository import KnowledgeRepository
from app.intelligence.status import build_enterprise_intelligence_status

ENTERPRISE_AI_READINESS_CONTRACT = "vaelqorix.enterprise_ai_readiness.v1"


def _check(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {
        "name": name,
        "status": "pass" if passed else "attention",
        "passed": passed,
        "detail": detail,
    }


def build_enterprise_ai_readiness(
    repository: KnowledgeRepository,
    *,
    ai_evaluation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    status = build_enterprise_intelligence_status(repository)
    rag = status["rag"]
    llm = status["llm"]
    mcp = status["mcp"]
    evaluation = ai_evaluation or {}
    evaluation_contract = evaluation.get("schema") == "vaelqorix.ai_evaluation.v1"
    sample_count = int(evaluation.get("sample_count") or 0)
    approved_rate = float(evaluation.get("approved_for_ares_rate") or 0.0)
    traceable_rate = float(evaluation.get("traceable_result_rate") or 0.0)

    checks = [
        _check(
            "persistent_memory",
            bool(rag.get("persistent")),
            "Knowledge documents use the persistent repository.",
        ),
        _check(
            "versioned_documents",
            bool(rag.get("versioned_documents")) and bool(rag.get("latest_versions")),
            "Knowledge documents expose stable versions and latest-version indexes.",
        ),
        _check(
            "llm_governance",
            llm.get("governance", {}).get("schema") == "vaelqorix.llm_governance.v1"
            and llm.get("governance", {}).get("ares_execution_requires_approved_contract") is True,
            "LLM decisions require governance evidence before ARES execution.",
        ),
        _check(
            "mcp_policy",
            bool(mcp.get("governed_execution")),
            "MCP action and tool policies are part of the execution contract.",
        ),
        _check(
            "ai_evaluation_contract",
            evaluation_contract,
            "RedQueen training report exposes enterprise AI evaluation metrics.",
        ),
        _check(
            "feedback_samples",
            sample_count > 0,
            "At least one RedQueen/ARES feedback sample is available for evaluation.",
        ),
        _check(
            "approved_ai_contracts",
            sample_count == 0 or approved_rate >= 0.95,
            "Evaluated decisions are approved for ARES at the required threshold.",
        ),
        _check(
            "traceable_results",
            sample_count == 0 or traceable_rate >= 0.95,
            "Evaluated executions include traceable result hashes.",
        ),
    ]
    passed = sum(1 for item in checks if item["passed"])
    failed = len(checks) - passed
    overall = "ready_for_controlled_pilot" if failed == 0 else "attention_required"
    if failed == 1 and sample_count == 0:
        overall = "contract_ready_waiting_for_feedback"

    return {
        "module": "enterprise_ai",
        "contract": ENTERPRISE_AI_READINESS_CONTRACT,
        "overall": overall,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "memory": {
            "provider": rag.get("provider"),
            "document_count": rag.get("document_count"),
            "storage_contract": rag.get("storage_contract"),
            "latest_versions": rag.get("latest_versions", {}),
        },
        "llm": {
            "decision_schema": llm.get("decision_schema"),
            "governance_schema": llm.get("governance", {}).get("schema"),
            "decision_trace_schema": llm.get("governance", {}).get("decision_trace_schema"),
        },
        "evaluation": {
            "schema": evaluation.get("schema", ""),
            "sample_count": sample_count,
            "approved_for_ares_rate": approved_rate,
            "traceable_result_rate": traceable_rate,
            "recommendations": evaluation.get("recommendations", []),
        },
    }
