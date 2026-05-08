from __future__ import annotations

import json
from collections import Counter
from typing import Any

from sqlalchemy.orm import Session

from app.models.execution_result import ExecutionResult
from app.models.verdict import Verdict


def _decode_json(raw: str, fallback: Any) -> Any:
    try:
        return json.loads(raw or "")
    except (TypeError, ValueError):
        return fallback


def _result_item(row: ExecutionResult) -> dict:
    evidence = _decode_json(row.evidence, [])
    rollback_events = 0
    if isinstance(evidence, list):
        rollback_events = sum(
            1
            for step in evidence
            if isinstance(step, dict) and str(step.get("status", "")).lower() == "rollback"
        )

    return {
        "id": row.id,
        "verdict_id": row.verdict_id,
        "status": row.status,
        "duration_ms": row.duration_ms,
        "error_code": row.error_code,
        "result_hash": row.result_hash,
        "timestamp": row.timestamp.isoformat(),
        "rollback_events": rollback_events,
    }


def read_ares_memory(db: Session, *, target: str, limit: int = 20) -> dict:
    normalized_target = target.strip()
    empty = {
        "target": normalized_target or target,
        "count": 0,
        "status_counts": {},
        "action_counts": {},
        "failure_rate": 0.0,
        "consecutive_failures": 0,
        "items": [],
    }
    if not normalized_target:
        return empty

    verdicts = (
        db.query(Verdict)
        .filter(Verdict.target == normalized_target)
        .order_by(Verdict.timestamp.desc())
        .limit(max(1, min(limit, 100)))
        .all()
    )
    verdict_by_id = {row.verdict_id: row for row in verdicts}
    if not verdict_by_id:
        return empty

    results = (
        db.query(ExecutionResult)
        .filter(ExecutionResult.verdict_id.in_(verdict_by_id.keys()))
        .order_by(ExecutionResult.timestamp.desc())
        .limit(max(1, min(limit, 100)))
        .all()
    )

    items: list[dict] = []
    status_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()

    for result in results:
        verdict = verdict_by_id.get(result.verdict_id)
        action_type = verdict.action_type if verdict else "unknown"
        status = result.status or "unknown"
        status_counts[status] += 1
        action_counts[action_type] += 1
        items.append(
            {
                **_result_item(result),
                "target": normalized_target,
                "action_type": action_type,
                "risk_score": verdict.risk_score if verdict else 0.0,
                "requires_human": verdict.requires_human if verdict else False,
            }
        )

    consecutive_failures = 0
    for item in items:
        if item["status"] == "success":
            break
        consecutive_failures += 1

    total = len(items)
    failed = sum(1 for item in items if item["status"] != "success")
    return {
        "target": normalized_target,
        "count": total,
        "status_counts": dict(status_counts),
        "action_counts": dict(action_counts),
        "failure_rate": round(failed / total, 4) if total else 0.0,
        "consecutive_failures": consecutive_failures,
        "last_result_hash": items[0]["result_hash"] if items else "",
        "items": items,
    }
