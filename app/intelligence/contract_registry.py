from __future__ import annotations

from typing import Any

ENTERPRISE_AI_CONTRACT_REGISTRY = "zenthra.enterprise_ai_contract_registry.v1"


def build_enterprise_ai_contract_registry() -> dict[str, Any]:
    contracts = [
        {
            "name": "knowledge_document",
            "schema": "zenthra.knowledge_document.v1",
            "status": "active",
            "producer_endpoints": ["/api/v1/secops/intelligence/documents"],
            "consumer_endpoints": ["/api/v1/secops/intelligence/enterprise/status"],
            "required_fields": [
                "doc_id",
                "version",
                "title",
                "domain",
                "summary",
                "content_hash",
            ],
            "evidence": ["content_hash", "version"],
        },
        {
            "name": "enterprise_memory",
            "schema": "zenthra.enterprise_memory.v1",
            "status": "active",
            "producer_endpoints": ["/api/v1/secops/intelligence/documents"],
            "consumer_endpoints": [
                "/api/v1/secops/intelligence/enterprise/status",
                "/api/v1/secops/intelligence/enterprise/readiness",
            ],
            "required_fields": ["persistent", "latest_versions", "storage_contract"],
            "evidence": ["latest_versions", "document_count"],
        },
        {
            "name": "llm_governance",
            "schema": "zenthra.llm_governance.v1",
            "status": "active",
            "producer_endpoints": ["/api/v1/redqueen/verdict"],
            "consumer_endpoints": [
                "/api/v1/ares/evidence/{verdict_id}",
                "/api/v1/redqueen/training/report",
            ],
            "required_fields": [
                "approved_for_ares",
                "schema_valid",
                "confidence_valid",
                "present_guardrails",
            ],
            "evidence": ["llm_governance", "guardrail_decisions"],
        },
        {
            "name": "llm_decision",
            "schema": "redqueen.llm_decision.v1",
            "status": "active",
            "producer_endpoints": ["/api/v1/redqueen/verdict"],
            "consumer_endpoints": [
                "/api/v1/ares/execute",
                "/api/v1/ares/evidence/{verdict_id}",
            ],
            "required_fields": [
                "schema",
                "domain",
                "action_type",
                "final_action_source",
                "guardrail_decisions",
            ],
            "evidence": ["llm_contract", "signature"],
        },
        {
            "name": "ai_evaluation",
            "schema": "zenthra.ai_evaluation.v1",
            "status": "active",
            "producer_endpoints": ["/api/v1/redqueen/training/report"],
            "consumer_endpoints": ["/api/v1/secops/intelligence/enterprise/readiness"],
            "required_fields": [
                "sample_count",
                "approved_for_ares_rate",
                "traceable_result_rate",
                "recommendations",
            ],
            "evidence": ["execution_result", "result_hash"],
        },
        {
            "name": "ares_ai_evidence_bundle",
            "schema": "zenthra.ares_ai_evidence_bundle.v1",
            "status": "active",
            "producer_endpoints": ["/api/v1/ares/evidence/{verdict_id}"],
            "consumer_endpoints": ["frontend", "soc_export", "audit_review"],
            "required_fields": [
                "verdict_id",
                "executions",
                "intelligence",
                "audit",
                "bundle_hash",
            ],
            "evidence": ["bundle_hash", "audit.records", "audit.verification"],
        },
        {
            "name": "enterprise_ai_readiness",
            "schema": "zenthra.enterprise_ai_readiness.v1",
            "status": "active",
            "producer_endpoints": ["/api/v1/secops/intelligence/enterprise/readiness"],
            "consumer_endpoints": ["frontend", "release_gate", "operator_runbook"],
            "required_fields": ["overall", "checks", "memory", "llm", "evaluation"],
            "evidence": ["checks", "evaluation.recommendations"],
        },
    ]
    return {
        "module": "enterprise_ai",
        "contract": ENTERPRISE_AI_CONTRACT_REGISTRY,
        "version": 1,
        "count": len(contracts),
        "contracts": contracts,
        "frontend_entrypoints": {
            "memory_status": "/api/v1/secops/intelligence/enterprise/status",
            "readiness": "/api/v1/secops/intelligence/enterprise/readiness",
            "contracts": "/api/v1/secops/intelligence/enterprise/contracts",
            "evidence_bundle": "/api/v1/ares/evidence/{verdict_id}",
            "training_report": "/api/v1/redqueen/training/report",
        },
        "secrets_exposed": False,
    }
