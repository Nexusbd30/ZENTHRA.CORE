from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.audit_store import list_audit_records, verify_audit_chain
from app.models.execution_result import ExecutionResult

ARES_AI_EVIDENCE_BUNDLE_CONTRACT = "vaelqorix.ares_ai_evidence_bundle.v1"


def _json_loads(value: str | None, fallback):
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def _execution_payload(row: ExecutionResult) -> dict[str, Any]:
    evidence = _json_loads(row.evidence, [])
    traces = [
        item
        for item in evidence
        if isinstance(item, dict) and item.get("kind") == "intelligence_trace"
    ]
    return {
        "id": row.id,
        "verdict_id": row.verdict_id,
        "ares_id": row.ares_id,
        "action_type": row.action_type,
        "target_entity": row.target_entity,
        "target_system": row.target_system,
        "status": row.status,
        "duration_ms": row.duration_ms,
        "error_code": row.error_code,
        "result_hash": row.result_hash,
        "timestamp": row.timestamp.isoformat(),
        "evidence_count": len(evidence) if isinstance(evidence, list) else 0,
        "intelligence_traces": traces,
    }


def _bundle_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_ares_ai_evidence_bundle(db: Session, *, verdict_id: str) -> dict[str, Any]:
    executions = list(
        db.scalars(
            select(ExecutionResult)
            .where(ExecutionResult.verdict_id == verdict_id)
            .order_by(desc(ExecutionResult.timestamp))
        ).all()
    )
    execution_payloads = [_execution_payload(row) for row in executions]
    traces = [
        trace
        for execution in execution_payloads
        for trace in execution.get("intelligence_traces", [])
        if isinstance(trace, dict)
    ]
    latest_trace = traces[0] if traces else {}
    audit_records = list_audit_records(db, verdict_id=verdict_id, limit=200)
    audit_payloads = [
        {
            "record_id": row.record_id,
            "sequence_number": row.sequence_number,
            "verdict_id": row.verdict_id,
            "actor": row.actor,
            "actor_role": row.actor_role,
            "tenant_id": row.tenant_id,
            "capability": row.capability,
            "request_id": row.request_id,
            "action": row.action,
            "hash_prev": row.hash_prev,
            "hash_self": row.hash_self,
            "content_hash": row.content_hash,
            "chain_hash": row.chain_hash,
            "timestamp": row.timestamp.isoformat(),
        }
        for row in audit_records
    ]
    audit_verification = verify_audit_chain(db)
    payload: dict[str, Any] = {
        "module": "ares",
        "contract": ARES_AI_EVIDENCE_BUNDLE_CONTRACT,
        "verdict_id": verdict_id,
        "status": "ok" if execution_payloads or audit_payloads else "not_found",
        "execution_count": len(execution_payloads),
        "audit_count": len(audit_payloads),
        "trace_count": len(traces),
        "executions": execution_payloads,
        "intelligence": {
            "trace_schema": "vaelqorix.llm_decision_trace.v1",
            "latest_trace": latest_trace,
            "llm_contract": latest_trace.get("llm_contract", {}) if latest_trace else {},
            "llm_governance": latest_trace.get("llm_governance", {}) if latest_trace else {},
            "mcp_action_policy": latest_trace.get("mcp_action_policy", {}) if latest_trace else {},
            "mcp_tool_policy": latest_trace.get("mcp_tool_policy", {}) if latest_trace else {},
            "rag_references": latest_trace.get("rag_references", []) if latest_trace else [],
        },
        "audit": {
            "hash_chain": "valid" if audit_verification.get("valid") else "invalid",
            "verification": audit_verification,
            "records": audit_payloads,
        },
    }
    payload["bundle_hash"] = _bundle_hash(payload)
    return payload
