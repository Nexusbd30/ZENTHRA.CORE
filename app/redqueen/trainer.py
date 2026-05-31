from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Any

from sqlalchemy.orm import Session

from app.intelligence.governance import LLM_DECISION_TRACE_SCHEMA, LLM_GOVERNANCE_SCHEMA
from app.models.execution_result import ExecutionResult
from app.models.verdict import Verdict


def _json_list(raw: str) -> list[str]:
    try:
        value = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item]


def _json_dict(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _confidence_bucket(confidence: float) -> str:
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.6:
        return "medium"
    return "low"


def _rate(success: int, total: int) -> float:
    return round(success / total, 4) if total else 0.0


def _build_ai_governance_report(
    verdicts: dict[str, Verdict],
    latest_results: dict[str, ExecutionResult],
) -> dict[str, Any]:
    total = 0
    approved = 0
    contract_present = 0
    traceable_results = 0
    missing_governance = 0
    guardrails: Counter[str] = Counter()
    final_sources: Counter[str] = Counter()

    for verdict_id, verdict in verdicts.items():
        result = latest_results.get(verdict_id)
        if result is None:
            continue
        total += 1
        controls = _json_dict(verdict.execution_controls)
        governance = controls.get("llm_governance")
        if isinstance(governance, dict):
            contract_present += 1
            if governance.get("approved_for_ares") is True:
                approved += 1
            for guardrail in governance.get("present_guardrails", []):
                guardrails[str(guardrail)] += 1
        else:
            missing_governance += 1

        contract = controls.get("llm_contract")
        if isinstance(contract, dict):
            final_sources[str(contract.get("final_action_source") or "unknown")] += 1

        if result.result_hash:
            traceable_results += 1

    recommendations: list[str] = []
    if missing_governance:
        recommendations.append("backfill_llm_governance_for_legacy_verdicts")
    if total and _rate(approved, total) < 1.0:
        recommendations.append("block_or_review_unapproved_llm_contracts")
    if total and _rate(traceable_results, total) < 1.0:
        recommendations.append("enforce_result_hash_for_ai_evidence")
    if not total:
        recommendations.append("collect_more_execution_feedback")

    return {
        "schema": "zenthra.ai_evaluation.v1",
        "llm_governance_schema": LLM_GOVERNANCE_SCHEMA,
        "decision_trace_schema": LLM_DECISION_TRACE_SCHEMA,
        "sample_count": total,
        "contract_presence_rate": _rate(contract_present, total),
        "approved_for_ares_rate": _rate(approved, total),
        "traceable_result_rate": _rate(traceable_results, total),
        "missing_governance_count": missing_governance,
        "guardrail_counts": dict(sorted(guardrails.items())),
        "final_action_sources": dict(sorted(final_sources.items())),
        "recommendations": recommendations,
    }


def build_training_report(db: Session, *, limit: int = 100) -> dict[str, Any]:
    verdicts = (
        db.query(Verdict)
        .order_by(Verdict.timestamp.desc())
        .limit(max(1, min(limit, 500)))
        .all()
    )
    verdict_by_id = {row.verdict_id: row for row in verdicts}
    if not verdict_by_id:
        return {
            "status": "insufficient_data",
            "sample_count": 0,
            "success_rate": 0.0,
            "action_performance": {},
            "confidence_buckets": {},
            "failure_factors": [],
            "ai_governance": _build_ai_governance_report({}, {}),
            "recommendations": ["collect_more_execution_feedback"],
        }

    results = (
        db.query(ExecutionResult)
        .filter(ExecutionResult.verdict_id.in_(verdict_by_id.keys()))
        .order_by(ExecutionResult.timestamp.desc())
        .all()
    )
    latest_result: dict[str, ExecutionResult] = {}
    for result in results:
        latest_result.setdefault(result.verdict_id, result)

    action_stats: dict[str, Counter[str]] = defaultdict(Counter)
    confidence_stats: dict[str, Counter[str]] = defaultdict(Counter)
    failure_factors: Counter[str] = Counter()
    total = 0
    success = 0

    for verdict_id, verdict in verdict_by_id.items():
        latest = latest_result.get(verdict_id)
        if latest is None:
            continue
        total += 1
        ok = latest.status == "success"
        if ok:
            success += 1
        outcome = "success" if ok else "failed"
        action_stats[verdict.action_type][outcome] += 1
        bucket = _confidence_bucket(float(verdict.confidence or 0.0))
        confidence_stats[bucket][outcome] += 1
        if not ok:
            failure_factors.update(_json_list(verdict.factors))

    recommendations: list[str] = []
    for action, stats in action_stats.items():
        attempts = stats["success"] + stats["failed"]
        if attempts >= 2 and _rate(stats["success"], attempts) < 0.5:
            recommendations.append(f"review_action_policy:{action}")
    high = confidence_stats.get("high", Counter())
    high_total = high["success"] + high["failed"]
    if high_total >= 2 and _rate(high["success"], high_total) < 0.75:
        recommendations.append("recalibrate_high_confidence_threshold")
    if total < 5:
        recommendations.append("collect_more_execution_feedback")
    if failure_factors:
        recommendations.append(f"inspect_failure_factor:{failure_factors.most_common(1)[0][0]}")

    return {
        "status": "ok" if total else "insufficient_data",
        "sample_count": total,
        "success_rate": _rate(success, total),
        "action_performance": {
            action: {
                "success": stats["success"],
                "failed": stats["failed"],
                "success_rate": _rate(stats["success"], stats["success"] + stats["failed"]),
            }
            for action, stats in sorted(action_stats.items())
        },
        "confidence_buckets": {
            bucket: {
                "success": stats["success"],
                "failed": stats["failed"],
                "success_rate": _rate(stats["success"], stats["success"] + stats["failed"]),
            }
            for bucket, stats in sorted(confidence_stats.items())
        },
        "failure_factors": [
            {"factor": factor, "count": count}
            for factor, count in failure_factors.most_common(10)
        ],
        "ai_governance": _build_ai_governance_report(verdict_by_id, latest_result),
        "recommendations": list(dict.fromkeys(recommendations)),
    }
