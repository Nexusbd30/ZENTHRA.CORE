from __future__ import annotations

from typing import Any

from app.core.mcp_gateway import list_mcp_tools
from app.intelligence.governance import build_llm_governance_status
from app.intelligence.llm_contract import LLM_DECISION_SCHEMA
from app.intelligence.repository import (
    KnowledgeRepository,
    document_to_payload,
    get_knowledge_repository,
)

MCP_CONTEXT_FIELDS: tuple[str, ...] = (
    "allowed_actions",
    "allowed_tools",
    "blocked_actions",
    "blocked_tools",
    "blast_radius",
    "criticality",
    "evidence_refs",
    "tools",
    "tool_results",
)


def build_intelligence_status(repository: KnowledgeRepository | None = None) -> dict[str, Any]:
    repository = repository or get_knowledge_repository()
    knowledge_documents = repository.list_documents()
    domains = sorted({doc.domain for doc in knowledge_documents})
    actions = sorted({action for doc in knowledge_documents for action in doc.recommended_actions})
    documents = [
        document_to_payload(doc)
        for doc in knowledge_documents
    ]
    return {
        "module": "intelligence",
        "mode": "local-defensive-core",
        "rag": {
            "provider": repository.provider,
            "document_count": len(knowledge_documents),
            "repository_contract": "zenthra.knowledge_repository.v1",
            "document_contract": "zenthra.knowledge_document.v1",
            "persistent": repository.provider != "in_memory",
            "versioned_documents": True,
            "domains": domains,
            "documents": documents,
        },
        "llm": {
            "decision_schema": LLM_DECISION_SCHEMA,
            "governance": build_llm_governance_status(),
            "contract_enforced": True,
            "fallback_guardrails": [
                "allowed_action_validation",
                "domain_action_validation",
                "minimum_action_enforcement",
                "confidence_clamping",
            ],
        },
        "mcp": {
            "context_schema": "zenthra.mcp_context.v1",
            "tool_policy_schema": "zenthra.mcp_tool_policy.v1",
            "tool_registry_mode": "local_registry",
            "supported_fields": list(MCP_CONTEXT_FIELDS),
            "registered_tools": list_mcp_tools(),
            "governed_execution": True,
        },
        "domains": domains,
        "recommended_actions": actions,
    }


def build_enterprise_intelligence_status(repository: KnowledgeRepository) -> dict[str, Any]:
    status = build_intelligence_status(repository)
    documents = status["rag"]["documents"]
    latest_versions: dict[str, int] = {}
    for document in documents:
        doc_id = str(document.get("doc_id") or "")
        latest_versions[doc_id] = max(
            latest_versions.get(doc_id, 0),
            int(document.get("version") or 1),
        )
    status["mode"] = "enterprise-memory-core"
    status["rag"]["storage_contract"] = "zenthra.enterprise_memory.v1"
    status["rag"]["latest_versions"] = latest_versions
    status["rag"]["ready_for_phase3"] = bool(status["rag"]["persistent"])
    return status
