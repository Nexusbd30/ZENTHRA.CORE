from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime


def build_execution_result(*, verdict: dict, execution: dict, actor: str = "ares") -> dict:
    record = {
        "verdict_id": verdict.get("verdict_id"),
        "ares_id": actor,
        "status": execution.get("status", "unknown"),
        "duration_ms": execution.get("duration_ms", 0),
        "evidence": execution.get("executed_steps", []),
        "error_code": "" if execution.get("status") == "success" else "execution_failed",
        "timestamp": datetime.now(UTC).isoformat(),
    }

    normalized = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    record["result_hash"] = hashlib.sha256(normalized).hexdigest()
    return record
