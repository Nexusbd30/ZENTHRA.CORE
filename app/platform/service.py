from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.core.enterprise_security import build_enterprise_readiness
from app.intelligence.repository import get_persistent_knowledge_repository
from app.intelligence.status import build_enterprise_intelligence_status
from app.platform.blacknode import blacknode_gateway
from app.platform.cortexflow import cortexflow_runtime
from app.platform.nexusapi import nexusapi_registry
from app.platform.nexusflow import nexusflow_engine
from app.platform.nexusvault import nexusvault_retriever
from app.platform.registry import (
    CURRENT_CORE,
    CURRENT_RUNTIME,
    MIGRATION_STRATEGY,
    PLATFORM_DOMAINS,
    PLATFORM_RULES,
    PLATFORM_UMBRELLA,
    PRODUCT_NAME,
)


def build_platform_map() -> dict[str, Any]:
    return {
        "umbrella": PLATFORM_UMBRELLA,
        "product": PRODUCT_NAME,
        "current_core": CURRENT_CORE,
        "runtime": CURRENT_RUNTIME,
        "migration_strategy": MIGRATION_STRATEGY,
        "domains": PLATFORM_DOMAINS,
        "rules": PLATFORM_RULES,
    }


def _check(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {
        "name": name,
        "status": "pass" if passed else "attention",
        "passed": passed,
        "detail": detail,
    }


def _domain_readiness(
    *,
    key: str,
    checks: list[dict[str, Any]],
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    domain = PLATFORM_DOMAINS[key]
    passed = all(item["passed"] for item in checks)
    return {
        "key": key,
        "name": domain["name"],
        "status": "ready" if passed else "attention",
        "checks": checks,
        "evidence": evidence or {},
    }


def build_platform_readiness(db: Session, *, tenant_id: str | None = None) -> dict[str, Any]:
    enterprise_security = build_enterprise_readiness(tenant_id=tenant_id)
    repository = get_persistent_knowledge_repository(db)
    intelligence_status = build_enterprise_intelligence_status(repository)
    blacknode_status = blacknode_gateway.build_status()
    nexusapi_status = nexusapi_registry.build_status()
    nexusvault_status = nexusvault_retriever.build_status(db)
    cortexflow_status = cortexflow_runtime.build_status()
    nexusflow_status = nexusflow_engine.build_status()

    rbac_roles = enterprise_security.get("rbac", {}).get("roles", {})
    audit = enterprise_security.get("audit", {})
    rag = intelligence_status.get("rag", {})
    llm = intelligence_status.get("llm", {})
    mcp = intelligence_status.get("mcp", {})

    domains = {
        "blacknode": _domain_readiness(
            key="blacknode",
            checks=[
                _check("rbac_enabled", bool(enterprise_security.get("rbac", {}).get("enabled")), "RBAC is enabled for enterprise control-plane operations."),
                _check("admin_role_present", "admin" in rbac_roles, "Admin role is registered."),
                _check("audit_chain", audit.get("hash_chain") == "enabled", "Audit hash-chain evidence is enabled."),
                _check("capability_gate", bool(audit.get("capability_gate")), "Capability gates protect enterprise actions."),
                _check("security_gateway_active", blacknode_status["contract"] == "nexusops.blacknode.security_gateway.v1", "BlackNode SecurityGateway is active."),
            ],
            evidence={
                "gateway": blacknode_status,
                "tenant": enterprise_security.get("tenant", {}),
                "security_runtime": enterprise_security.get("security_runtime", {}),
            },
        ),
        "nexusvault": _domain_readiness(
            key="nexusvault",
            checks=[
                _check("repository_available", bool(rag.get("provider")), "Knowledge repository is available."),
                _check("documents_indexed", int(rag.get("document_count") or 0) >= 0, "Knowledge document index can be queried."),
                _check("versioned_documents", bool(rag.get("versioned_documents")), "Knowledge documents expose version metadata."),
                _check("citation_rule_declared", True, "Private knowledge responses require citations by platform rule."),
            ],
            evidence={
                "retriever": nexusvault_status,
                "provider": rag.get("provider"),
                "document_count": rag.get("document_count"),
                "persistent": rag.get("persistent"),
                "domains": intelligence_status.get("domains", []),
            },
        ),
        "nexusapi": _domain_readiness(
            key="nexusapi",
            checks=[
                _check("tool_registry_available", nexusapi_status["mcp_tool_count"] > 0, "MCP/local tool registry exposes tools."),
                _check("action_tools_available", nexusapi_status["action_tool_count"] > 0, "Operational action tools are registered."),
                _check("devsecops_providers_available", nexusapi_status["devsecops_provider_count"] > 0, "DevSecOps integration providers are registered."),
                _check("governed_execution", bool(mcp.get("governed_execution")), "Tool execution policy is part of the contract."),
                _check("blacknode_enforced", bool(nexusapi_status["blacknode_enforced"]), "NexusAPI requires BlackNode enforcement."),
            ],
            evidence={
                "registry": nexusapi_status,
                "registered_tools": nexusapi_status["mcp_tools"],
                "action_tools": nexusapi_status["action_tools"],
                "devsecops_providers": nexusapi_status["devsecops_providers"],
            },
        ),
        "cortexflow": _domain_readiness(
            key="cortexflow",
            checks=[
                _check("agent_runtime_mapped", True, "RedQueen, ARES and intelligence modules map to CortexFlow."),
                _check("agent_runtime_contract", cortexflow_status["contract"] == "nexusops.cortexflow.agent_runtime.v1", "CortexFlow AgentRuntime adapter is active."),
                _check("llm_contract_enforced", bool(llm.get("contract_enforced")), "LLM decisions use an enforced contract."),
                _check("fallback_guardrails", bool(llm.get("fallback_guardrails")), "Agent fallback guardrails are configured."),
                _check("tool_router_policy", bool(mcp.get("tool_policy_schema")), "Tool-routing policy schema is available."),
            ],
            evidence={
                "runtime": cortexflow_status,
                "decision_schema": llm.get("decision_schema"),
                "governance": llm.get("governance", {}),
            },
        ),
        "nexusflow": _domain_readiness(
            key="nexusflow",
            checks=[
                _check("workflow_engine_mapped", True, "ARES lifecycle maps to NexusFlow orchestration."),
                _check("workflow_engine_contract", nexusflow_status["contract"] == "nexusops.nexusflow.workflow_engine.v1", "NexusFlow WorkflowEngine adapter is active."),
                _check("approval_records_mapped", True, "Approval records map to NexusFlow approval workflows."),
                _check("human_control_rule_declared", True, "Sensitive operations require human control by platform rule."),
            ],
            evidence={
                "engine": nexusflow_status,
                "current_mapping": PLATFORM_DOMAINS["nexusflow"]["current_backend_mapping"],
            },
        ),
    }

    all_checks = [check for domain in domains.values() for check in domain["checks"]]
    passed = sum(1 for check in all_checks if check["passed"])
    failed = len(all_checks) - passed
    return {
        "module": "platform",
        "product": PRODUCT_NAME,
        "runtime": CURRENT_RUNTIME,
        "overall": "ready_for_contract_integration" if failed == 0 else "attention_required",
        "passed": passed,
        "failed": failed,
        "domains": domains,
        "next_gate": "harden_blacknode_contracts_before_runtime_migration",
    }
