from __future__ import annotations

from typing import Any

PLATFORM_UMBRELLA = "NEXUSBIGDATA"
PRODUCT_NAME = "NexusOps AI"
CURRENT_CORE = "ZENTHRA.CORE_SECURITY"
CURRENT_RUNTIME = "app.main:app"
MIGRATION_STRATEGY = "incremental_modular_monolith"

PLATFORM_RULES = [
    "No business logic inside routers.",
    "No AI execution without BlackNode validation.",
    "No tool execution without permission checks.",
    "No private-document answer without citations.",
    "No secret ever reaches the LLM.",
    "DevSecOps vertical logic lives outside the core platform.",
    "CortexFlow reasons. NexusFlow orchestrates. BlackNode governs.",
]

PLATFORM_DOMAINS: dict[str, dict[str, Any]] = {
    "cortexflow": {
        "key": "cortexflow",
        "name": "CortexFlow",
        "layer": "intelligence",
        "status": "mapped_to_existing_backend",
        "responsibilities": [
            "reasoning",
            "planning",
            "agent_lifecycle",
            "context_building",
            "tool_routing",
            "response_generation",
            "memory_coordination",
        ],
        "current_backend_mapping": [
            "app.redqueen",
            "app.ares",
            "app.intelligence",
        ],
        "contracts": ["AgentRuntime"],
        "notes": ["Runtime migration is intentionally deferred."],
    },
    "nexusflow": {
        "key": "nexusflow",
        "name": "NexusFlow",
        "layer": "orchestration",
        "status": "mapped_to_existing_backend",
        "responsibilities": [
            "workflows",
            "triggers",
            "events",
            "queues",
            "schedules",
            "human_approvals",
            "escalations",
            "multi_step_operations",
        ],
        "current_backend_mapping": [
            "app.ares",
            "app.services.autonomy_service",
            "app.models.approval_record",
        ],
        "contracts": ["WorkflowEngine"],
        "notes": ["ARES lifecycle and approval records are the current orchestration base."],
    },
    "blacknode": {
        "key": "blacknode",
        "name": "BlackNode",
        "layer": "security_governance",
        "status": "mapped_to_existing_backend",
        "responsibilities": [
            "authentication",
            "authorization",
            "rbac",
            "policy_enforcement",
            "audit_trails",
            "prompt_injection_protection",
            "risk_scoring",
            "approval_enforcement",
        ],
        "current_backend_mapping": [
            "app.core.security",
            "app.core.enterprise_security",
            "app.middlewares.audit_middleware",
            "app.models.audit_record",
            "app.ares.approval",
        ],
        "contracts": ["SecurityGateway"],
        "notes": ["BlackNode remains the first domain to harden before deeper agent migration."],
    },
    "nexusvault": {
        "key": "nexusvault",
        "name": "NexusVault",
        "layer": "knowledge_memory",
        "status": "mapped_to_existing_backend",
        "responsibilities": [
            "document_ingestion",
            "text_extraction",
            "chunking",
            "embeddings",
            "retrieval",
            "reranking",
            "citations",
            "enterprise_memory",
        ],
        "current_backend_mapping": [
            "app.intelligence",
            "app.db.vector",
            "app.models.knowledge_document",
        ],
        "contracts": ["KnowledgeRetriever"],
        "notes": ["Private knowledge answers must remain citation-ready."],
    },
    "nexusapi": {
        "key": "nexusapi",
        "name": "NexusAPI",
        "layer": "integrations_tools",
        "status": "mapped_to_existing_backend",
        "responsibilities": [
            "tool_registry",
            "external_apis",
            "github",
            "jira",
            "slack",
            "cloud_providers",
            "databases",
            "webhooks",
            "tool_call_audit",
        ],
        "current_backend_mapping": [
            "app.actions",
            "app.identity",
            "app.secops",
            "app.ingestion",
        ],
        "contracts": ["ToolRegistry"],
        "notes": ["Tools must be risk-classified, permission-checked and audited."],
    },
}

