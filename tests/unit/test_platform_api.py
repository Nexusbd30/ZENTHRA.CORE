from __future__ import annotations

import pytest

from app.ares.validator import validate_verdict
from app.core.settings import settings
from app.core.signing import sign_payload
from app.platform.blacknode import blacknode_gateway, classify_action_risk
from app.platform.vaelqorixapi import vaelqorixapi_registry


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "VAELQORIX_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


@pytest.mark.asyncio
async def test_platform_map_exposes_vaelqorix_domain_boundaries(test_client, monkeypatch):
    response = await test_client.get(
        "/api/v1/platform/map",
        headers=monitor_headers(monkeypatch),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["umbrella"] == "VAELQORIX"
    assert body["product"] == "VAELQORIX AI"
    assert body["current_core"] == "VAELQORIX.XDR_COMMAND"
    assert body["runtime"] == "app.main:app"
    assert body["migration_strategy"] == "incremental_modular_monolith"

    domains = body["domains"]
    assert set(domains) == {
        "cortexflow",
        "vaelqorixflow",
        "blacknode",
        "vaelqorixvault",
        "vaelqorixapi",
    }
    assert domains["cortexflow"]["contracts"] == ["AgentRuntime"]
    assert "app.redqueen" in domains["cortexflow"]["current_backend_mapping"]
    assert domains["vaelqorixflow"]["contracts"] == ["WorkflowEngine"]
    assert "app.ares" in domains["vaelqorixflow"]["current_backend_mapping"]
    assert domains["blacknode"]["contracts"] == ["SecurityGateway"]
    assert "app.core.enterprise_security" in domains["blacknode"]["current_backend_mapping"]
    assert domains["vaelqorixvault"]["contracts"] == ["KnowledgeRetriever"]
    assert "app.intelligence" in domains["vaelqorixvault"]["current_backend_mapping"]
    assert domains["vaelqorixapi"]["contracts"] == ["ToolRegistry"]
    assert "app.secops" in domains["vaelqorixapi"]["current_backend_mapping"]
    assert "No AI execution without BlackNode validation." in body["rules"]


@pytest.mark.asyncio
async def test_platform_readiness_exposes_domain_statuses(test_client, monkeypatch):
    response = await test_client.get(
        "/api/v1/platform/readiness",
        headers={
            **monitor_headers(monkeypatch),
            "X-Tenant-ID": "tenant-platform",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["module"] == "platform"
    assert body["product"] == "VAELQORIX AI"
    assert body["runtime"] == "app.main:app"
    assert body["overall"] == "ready_for_contract_integration"
    assert body["failed"] == 0
    assert body["next_gate"] == "harden_blacknode_contracts_before_runtime_migration"

    domains = body["domains"]
    assert set(domains) == {
        "cortexflow",
        "vaelqorixflow",
        "blacknode",
        "vaelqorixvault",
        "vaelqorixapi",
    }
    assert domains["blacknode"]["status"] == "ready"
    assert domains["blacknode"]["evidence"]["tenant"]["tenant_id"] == "tenant-platform"
    assert domains["blacknode"]["evidence"]["gateway"]["contract"] == (
        "vaelqorix.blacknode.security_gateway.v1"
    )
    blacknode_checks = {item["name"]: item for item in domains["blacknode"]["checks"]}
    assert blacknode_checks["rbac_enabled"]["passed"] is True
    assert blacknode_checks["audit_chain"]["passed"] is True
    assert blacknode_checks["security_gateway_active"]["passed"] is True

    assert domains["vaelqorixvault"]["status"] == "ready"
    assert domains["vaelqorixvault"]["evidence"]["retriever"]["contract"] == (
        "vaelqorix.vaelqorixvault.knowledge_retriever.v1"
    )
    assert domains["vaelqorixvault"]["evidence"]["provider"]
    assert "domains" in domains["vaelqorixvault"]["evidence"]

    assert domains["vaelqorixapi"]["status"] == "ready"
    assert domains["vaelqorixapi"]["evidence"]["registry"]["contract"] == (
        "vaelqorix.vaelqorixapi.tool_registry.v1"
    )
    assert domains["vaelqorixapi"]["evidence"]["registered_tools"]
    assert domains["vaelqorixapi"]["evidence"]["action_tools"]
    provider_names = {
        item["provider"] for item in domains["vaelqorixapi"]["evidence"]["devsecops_providers"]
    }
    assert "github_actions" in provider_names

    cortex_checks = {item["name"]: item for item in domains["cortexflow"]["checks"]}
    assert cortex_checks["agent_runtime_contract"]["passed"] is True
    assert cortex_checks["llm_contract_enforced"]["passed"] is True
    assert cortex_checks["fallback_guardrails"]["passed"] is True

    vaelqorixflow_checks = {item["name"]: item for item in domains["vaelqorixflow"]["checks"]}
    assert vaelqorixflow_checks["workflow_engine_contract"]["passed"] is True


def _signed_verdict(**overrides):
    verdict = {
        "verdict_id": "verdict-platform-blacknode",
        "timestamp": "2026-06-16T00:00:00Z",
        "target": "repository:vaelqorix/core",
        "action_type": "block_deployment",
        "risk_score": 92.0,
        "confidence": 0.95,
        "factors": ["devsecops_secret_detected:true"],
        "policy_check": True,
        "requires_human": True,
        "justification_xai": "critical DevSecOps risk",
        "execution_controls": {
            "dry_run": True,
            "devsecops_provider": "github_actions",
            "mcp_context": {
                "tools": ["pipeline.lookup"],
                "evidence_refs": ["case-platform-1"],
            },
        },
    }
    verdict.update(overrides)
    verdict["signature"] = sign_payload({key: value for key, value in verdict.items() if key != "signature"})
    return verdict


def test_blacknode_gateway_governs_ares_verdict_validation():
    verdict = _signed_verdict()

    gateway_decision = blacknode_gateway.validate_verdict(verdict)
    legacy_result = validate_verdict(verdict)

    assert gateway_decision.allowed is True
    assert gateway_decision.code == "ok"
    assert gateway_decision.risk_level == "approval_required"
    assert gateway_decision.evidence["mcp_tool_policy"]["allowed"] is True
    assert legacy_result.valid is True
    assert legacy_result.code == "ok"


def test_blacknode_gateway_denies_unknown_mcp_tool_through_ares_validator():
    verdict = _signed_verdict(
        execution_controls={
            "dry_run": True,
            "devsecops_provider": "github_actions",
            "mcp_context": {"tools": ["unknown.tool"]},
        }
    )

    result = validate_verdict(verdict)

    assert result.valid is False
    assert result.code == "mcp_tool_unknown"


def test_vaelqorixapi_registry_classifies_action_tools():
    status = vaelqorixapi_registry.build_status()
    actions = {item["name"]: item for item in status["action_tools"]}

    assert status["contract"] == "vaelqorix.vaelqorixapi.tool_registry.v1"
    assert status["blacknode_enforced"] is True
    assert actions["block_deployment"]["risk_level"] == "approval_required"
    assert actions["block_deployment"]["requires_blacknode"] is True
    assert classify_action_risk("observe") == "read_only"
    assert classify_action_risk("block_deployment", 92.0) == "approval_required"
