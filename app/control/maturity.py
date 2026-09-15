from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.settings import settings
from app.models.execution_result import ExecutionResult
from app.models.threat_event import ThreatEvent
from app.models.verdict import Verdict


def _level(score: int) -> str:
    if score >= 85:
        return "L4 production_candidate"
    if score >= 70:
        return "L3 preproduction_ready"
    if score >= 50:
        return "L2 pilot_ready"
    if score >= 30:
        return "L1 prototype"
    return "L0 concept"


def _count(db: Session, model) -> int:
    return int(db.scalar(select(func.count()).select_from(model)) or 0)


def _average(values: Iterable[int]) -> int:
    values = list(values)
    if not values:
        return 0
    return round(sum(values) / len(values))


def redqueen_maturity(db: Session) -> dict:
    verdicts = _count(db, Verdict)
    events = _count(db, ThreatEvent)
    dimensions: list[dict[str, Any]] = [
        {
            "key": "decision_contract",
            "label": "Decision contract",
            "score": 88,
            "evidence": [
                "signed_verdicts",
                "allowed_action_validation",
                "policy_matrix_enforced",
                "llm_contract_normalization",
            ],
            "weaknesses": [
                "confidence still depends on heuristic and provider signal quality",
                "needs calibrated thresholds from real incident history",
            ],
            "rectification": [
                "add evaluation dataset with true_positive false_positive labels",
                "track precision recall and false positive rate per provider",
            ],
        },
        {
            "key": "attack_reasoning",
            "label": "Attack reasoning",
            "score": 82,
            "evidence": [
                "causal_chain",
                "attack_anticipation",
                "bridge_trace",
                "strategic_anticipation",
                "attack_reality_analysis",
            ],
            "weaknesses": [
                "causal chain is explainable but not yet learned from large real telemetry",
                "limited temporal graph persistence across long campaigns",
            ],
            "rectification": [
                "persist campaign graphs by entity and tenant",
                "add analyst feedback loop to tune stage transitions",
            ],
        },
        {
            "key": "memory_and_learning",
            "label": "Memory and learning",
            "score": 72,
            "evidence": [
                "risk_memory",
                "drift_analysis",
                "training_report",
                "vector_memory_interface",
            ],
            "weaknesses": [
                "local or in-memory retrieval is not enough for enterprise scale",
                "model drift is detected but not yet auto-calibrated from production labels",
            ],
            "rectification": [
                "select pgvector qdrant or azure ai search as production retrieval backend",
                "store analyst dispositions and feed them into scoring calibration",
            ],
        },
        {
            "key": "integration_readiness",
            "label": "Integration readiness",
            "score": 67,
            "evidence": [
                "identity_event_flow",
                "devsecops_signal_flow",
                "soc_materialization",
                "provider_readiness_contracts",
            ],
            "weaknesses": [
                "real provider credentials and sandbox contract tests are still external gates",
                "production tenant isolation must be proven against real identity policy",
            ],
            "rectification": [
                "connect one real Entra tenant and one DevSecOps provider in staging",
                "run tenant isolation and provider contract tests with real permissions",
            ],
        },
    ]
    score = _average(item["score"] for item in dimensions)
    return {
        "module": "redqueen",
        "concept": "defensive autonomous reasoning brain that converts telemetry into signed risk verdicts",
        "maturity_score": score,
        "maturity_level": _level(score),
        "telemetry": {
            "verdicts": verdicts,
            "threat_events": events,
            "ai_enabled": bool(settings.AI_ENABLED),
            "ai_provider": settings.AI_PROVIDER,
            "autonomy_target": int(settings.REDQUEEN_AUTONOMY_MAX),
        },
        "strengths": [
            "clear separation between decision and execution",
            "signed verdict payloads with policy and human approval signals",
            "attack anticipation and causal explanation already integrated",
            "works in controlled pilot mode without requiring live providers",
        ],
        "weaknesses": [
            "needs real-world labelled data to prove detection accuracy",
            "provider signal quality is still the main limiting factor",
            "retrieval and long-term campaign memory need production backend selection",
            "LLM fallback is safe but limits reasoning depth when no real model is configured",
        ],
        "rectification_priority": [
            "build labelled evaluation set for true positive and false positive verdicts",
            "connect real identity DevSecOps and SOC sources in staging",
            "persist campaign graph memory across entities tenants and incidents",
            "measure precision recall mean time to verdict and analyst override rate",
        ],
        "dimensions": dimensions,
    }


def ares_maturity(db: Session) -> dict:
    executions = _count(db, ExecutionResult)
    verdicts = _count(db, Verdict)
    dimensions: list[dict[str, Any]] = [
        {
            "key": "execution_governance",
            "label": "Execution governance",
            "score": 86,
            "evidence": [
                "kill_switch",
                "internal_firewall",
                "human_approval",
                "signed_approval_evidence",
                "rollback_records",
            ],
            "weaknesses": [
                "multi-replica kill switch requires Redis validation in production",
                "live disruptive actions require provider-side idempotency evidence",
            ],
            "rectification": [
                "validate Redis-backed kill switch rate limit and replay guard in staging",
                "run provider sandbox tests for every disruptive action",
            ],
        },
        {
            "key": "response_planning",
            "label": "Response planning",
            "score": 83,
            "evidence": [
                "os_business_shield",
                "aggressive_containment",
                "enterprise_active_defense",
                "response_fabric",
                "hunter_trace",
            ],
            "weaknesses": [
                "plans are contract-ready but not yet proven against live enterprise connectors",
                "business impact scoring needs real service dependency data",
            ],
            "rectification": [
                "connect CMDB or asset criticality source",
                "run tabletop and dry-run exercises against staging providers",
            ],
        },
        {
            "key": "evidence_and_audit",
            "label": "Evidence and audit",
            "score": 88,
            "evidence": [
                "audit_hash_chain",
                "execution_result_hash",
                "approval_records",
                "ares_evidence_bundle",
                "legal_escalation_pack_contract",
            ],
            "weaknesses": [
                "external evidence storage and retention policy still need production configuration",
                "chain verification must be monitored continuously after deployment",
            ],
            "rectification": [
                "define immutable evidence storage target and retention policy",
                "add scheduled audit-chain verification alert",
            ],
        },
        {
            "key": "expulsion_capability",
            "label": "Expulsion capability",
            "score": 74,
            "evidence": [
                "hunter_trace_presence_state",
                "eviction_plan",
                "verify_eviction_step",
                "dry_run_ctf_mode",
            ],
            "weaknesses": [
                "hunter trace depends on available telemetry, not endpoint live collection yet",
                "expulsion steps are recommended and gated until provider integrations are live",
            ],
            "rectification": [
                "connect EDR IAM DNS firewall and SIEM providers for live read-back",
                "add eviction success checks per provider and asset type",
            ],
        },
    ]
    score = _average(item["score"] for item in dimensions)
    return {
        "module": "ares",
        "concept": "defensive execution and response control plane that validates RedQueen orders and applies governed containment",
        "maturity_score": score,
        "maturity_level": _level(score),
        "telemetry": {
            "executions": executions,
            "verdicts_available": verdicts,
            "action_execution_mode": settings.ACTION_EXECUTION_MODE,
            "kill_switch_backend": settings.ARES_KILL_SWITCH_BACKEND,
            "rate_limit_backend": settings.RATE_LIMIT_BACKEND,
            "replay_guard_backend": settings.REPLAY_GUARD_BACKEND,
        },
        "strengths": [
            "strong execution guardrails before real actions",
            "kill switch internal firewall approvals and rollback are first-class controls",
            "hunter trace now prepares expulsion without crossing defensive boundaries",
            "evidence bundle and audit chain support operator accountability",
        ],
        "weaknesses": [
            "live execution maturity depends on real provider credentials and read-back APIs",
            "Redis-backed distributed safety state still needs environment validation",
            "business impact protection needs real asset dependency mapping",
            "expulsion verification is contract-level until EDR IAM and network providers are connected",
        ],
        "rectification_priority": [
            "prove distributed kill switch replay guard and rate limits with Redis",
            "connect one live EDR or IAM provider read-back path for expulsion verification",
            "add provider contract tests for idempotency rollback and evidence",
            "run CTF/tabletop drills and record analyst overrides",
        ],
        "dimensions": dimensions,
    }


def autonomy_control_maturity(db: Session) -> dict:
    redqueen = redqueen_maturity(db)
    ares = ares_maturity(db)
    overall = _average([redqueen["maturity_score"], ares["maturity_score"]])
    return {
        "module": "autonomy_control",
        "schema": "vaelqorix.autonomy_control.maturity.v1",
        "overall_score": overall,
        "overall_level": _level(overall),
        "concept": "RedQueen decides defensively, ARES validates and executes only inside governed owned environments",
        "redqueen": redqueen,
        "ares": ares,
        "shared_rectification": [
            "connect real telemetry providers in staging before infrastructure production",
            "create labelled CTF and incident replay datasets",
            "measure detection quality and response quality separately",
            "keep live disruptive execution gated by preflight approval kill switch and audit evidence",
        ],
    }
