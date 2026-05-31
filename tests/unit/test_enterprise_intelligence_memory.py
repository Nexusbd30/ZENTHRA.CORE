from __future__ import annotations

from datetime import datetime

import pytest

from app.core.settings import settings
from app.intelligence.contracts import KnowledgeDocument
from app.intelligence.readiness import build_enterprise_ai_readiness
from app.intelligence.repository import (
    document_content_hash,
    document_to_payload,
    get_persistent_knowledge_repository,
)
from app.intelligence.status import build_enterprise_intelligence_status
from app.models.execution_result import ExecutionResult
from app.models.verdict import Verdict


def monitor_headers(monkeypatch):
    monkeypatch.setattr(settings, "ZENTHRA_MONITOR_TOKEN", "monitor-test-token")
    return {"Authorization": "Bearer monitor-test-token"}


def test_persistent_knowledge_repository_versions_and_search(db_session):
    repository = get_persistent_knowledge_repository(db_session)
    first = repository.upsert_document(
        KnowledgeDocument(
            doc_id="identity-lockdown-playbook",
            version=1,
            title="Identity Lockdown",
            domain="identity",
            tags=("identity", "lockdown", "entra"),
            summary="Contain compromised privileged identity.",
            recommended_actions=("identity_lockdown", "revoke_session"),
            evidence_requirements=("identity_activity", "change_ticket"),
            source="test",
            metadata={"owner": "secops"},
        )
    )
    second = repository.upsert_document(
        KnowledgeDocument(
            doc_id="identity-lockdown-playbook",
            version=2,
            title="Identity Lockdown v2",
            domain="identity",
            tags=("identity", "mfa", "entra"),
            summary="Contain compromised identity with MFA and session revocation.",
            recommended_actions=("require_mfa", "revoke_session"),
            evidence_requirements=("identity_activity", "provider_preflight"),
            source="test",
            metadata={"owner": "identity"},
        )
    )

    assert first.version == 1
    assert second.version == 2
    assert document_content_hash(first) != document_content_hash(second)
    assert document_to_payload(second)["contract"] == "zenthra.knowledge_document.v1"

    versions = repository.list_versions("identity-lockdown-playbook")
    assert [doc.version for doc in versions] == [2, 1]

    references = repository.search(
        query="entra mfa session",
        domain="identity",
        factors=["identity_lockdown"],
        limit=3,
    )
    assert references[0].doc_id == "identity-lockdown-playbook"
    assert references[0].domain == "identity"

    status = build_enterprise_intelligence_status(repository)
    assert status["mode"] == "enterprise-memory-core"
    assert status["rag"]["persistent"] is True
    assert status["rag"]["versioned_documents"] is True
    assert status["rag"]["latest_versions"]["identity-lockdown-playbook"] == 2
    assert status["rag"]["ready_for_phase3"] is True


@pytest.mark.asyncio
async def test_enterprise_intelligence_api_exposes_status_and_documents(
    test_client,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)
    payload = {
        "doc_id": "devsecops-release-gate",
        "version": 1,
        "title": "DevSecOps Release Gate",
        "domain": "devsecops",
        "tags": ["release", "github", "ghas"],
        "summary": "Block or gate risky production deployments.",
        "recommended_actions": ["require_release_approval", "block_deployment"],
        "evidence_requirements": ["repository", "pipeline_run", "change_ticket"],
        "source": "operator",
        "metadata": {"severity": "high"},
    }

    created = await test_client.post(
        "/api/v1/secops/intelligence/documents",
        headers=headers,
        json=payload,
    )
    assert created.status_code == 200
    body = created.json()
    assert body["doc_id"] == "devsecops-release-gate"
    assert body["version"] == 1
    assert body["content_hash"]
    assert body["contract"] == "zenthra.knowledge_document.v1"

    listed = await test_client.get(
        "/api/v1/secops/intelligence/documents",
        headers=headers,
    )
    assert listed.status_code == 200
    assert any(item["doc_id"] == "devsecops-release-gate" for item in listed.json())

    status = await test_client.get(
        "/api/v1/secops/intelligence/enterprise/status",
        headers=headers,
    )
    assert status.status_code == 200
    status_body = status.json()
    assert status_body["module"] == "intelligence"
    assert status_body["mode"] == "enterprise-memory-core"
    assert status_body["rag"]["storage_contract"] == "zenthra.enterprise_memory.v1"
    assert status_body["rag"]["persistent"] is True
    assert status_body["rag"]["latest_versions"]["devsecops-release-gate"] == 1


def test_enterprise_ai_readiness_combines_memory_governance_and_evaluation(db_session):
    repository = get_persistent_knowledge_repository(db_session)
    repository.upsert_document(
        KnowledgeDocument(
            doc_id="enterprise-ai-readiness",
            version=1,
            title="Enterprise AI Readiness",
            domain="generic",
            tags=("ai", "governance"),
            summary="Validate enterprise AI contracts before production use.",
            recommended_actions=("observe",),
            evidence_requirements=("llm_governance", "result_hash"),
            source="test",
        )
    )

    readiness = build_enterprise_ai_readiness(
        repository,
        ai_evaluation={
            "schema": "zenthra.ai_evaluation.v1",
            "sample_count": 2,
            "approved_for_ares_rate": 1.0,
            "traceable_result_rate": 1.0,
            "recommendations": [],
        },
    )

    assert readiness["contract"] == "zenthra.enterprise_ai_readiness.v1"
    assert readiness["overall"] == "ready_for_controlled_pilot"
    assert readiness["memory"]["storage_contract"] == "zenthra.enterprise_memory.v1"
    assert readiness["llm"]["governance_schema"] == "zenthra.llm_governance.v1"
    assert readiness["evaluation"]["schema"] == "zenthra.ai_evaluation.v1"
    assert all(check["passed"] for check in readiness["checks"])


@pytest.mark.asyncio
async def test_enterprise_ai_readiness_api_exposes_operational_gate(
    test_client,
    db_session,
    monkeypatch,
):
    headers = monitor_headers(monkeypatch)
    repository = get_persistent_knowledge_repository(db_session)
    repository.upsert_document(
        KnowledgeDocument(
            doc_id="enterprise-ai-api-readiness",
            version=1,
            title="Enterprise AI API Readiness",
            domain="identity",
            tags=("ai", "identity"),
            summary="Identity AI readiness contract.",
            recommended_actions=("require_mfa",),
            evidence_requirements=("llm_governance",),
            source="test",
        )
    )
    db_session.add(
        Verdict(
            verdict_id="enterprise-ai-ready-verdict",
            timestamp=datetime.utcnow(),
            target="user:alice@corp.com",
            action_type="require_mfa",
            risk_score=70,
            confidence=0.8,
            factors="[]",
            justification_xai="test",
            policy_check=True,
            requires_human=False,
            execution_controls=(
                '{"llm_contract":{"schema":"redqueen.llm_decision.v1",'
                '"final_action_source":"llm"},"llm_governance":'
                '{"schema":"zenthra.llm_governance.v1","approved_for_ares":true,'
                '"present_guardrails":["action_validation","minimum_action_enforcement"]}}'
            ),
            signature="sig",
        )
    )
    db_session.add(
        ExecutionResult(
            verdict_id="enterprise-ai-ready-verdict",
            ares_id="ares",
            action_type="require_mfa",
            target_entity="user:alice@corp.com",
            status="success",
            duration_ms=1,
            evidence="[]",
            result_hash="enterprise-ai-ready-hash",
            timestamp=datetime.utcnow(),
        )
    )
    db_session.commit()

    response = await test_client.get(
        "/api/v1/secops/intelligence/enterprise/readiness",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["module"] == "enterprise_ai"
    assert body["contract"] == "zenthra.enterprise_ai_readiness.v1"
    assert body["overall"] in {
        "ready_for_controlled_pilot",
        "attention_required",
        "contract_ready_waiting_for_feedback",
    }
    assert {check["name"] for check in body["checks"]} >= {
        "persistent_memory",
        "llm_governance",
        "ai_evaluation_contract",
        "traceable_results",
    }
    assert body["evaluation"]["sample_count"] >= 1
    assert body["evaluation"]["traceable_result_rate"] > 0.0
