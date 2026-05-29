from __future__ import annotations

from typing import Any

from app.core.mcp_gateway import list_mcp_tools
from app.intelligence.llm_contract import LLM_DECISION_SCHEMA
from app.intelligence.repository import get_knowledge_repository

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


def build_intelligence_status() -> dict[str, Any]:
    repository = get_knowledge_repository()
    knowledge_documents = repository.list_documents()
    domains = sorted({doc.domain for doc in knowledge_documents})
    actions = sorted({action for doc in knowledge_documents for action in doc.recommended_actions})
    documents = [
        {
            "doc_id": doc.doc_id,
            "title": doc.title,
            "domain": doc.domain,
            "tags": list(doc.tags),
            "recommended_actions": list(doc.recommended_actions),
            "evidence_requirements": list(doc.evidence_requirements),
        }
        for doc in knowledge_documents
    ]
    return {
        "module": "intelligence",
        "mode": "local-defensive-core",
        "rag": {
            "provider": repository.provider,
            "document_count": len(knowledge_documents),
            "repository_contract": "zenthra.knowledge_repository.v1",
            "domains": domains,
            "documents": documents,
        },
        "llm": {
            "decision_schema": LLM_DECISION_SCHEMA,
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
