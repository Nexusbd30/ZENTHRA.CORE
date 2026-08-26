from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4


def build_evidence_artifact(
    *,
    case_id: str,
    artifact_type: str,
    payload: dict[str, Any],
    classification: str = "confidential",
) -> dict[str, Any]:
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {
        "artifact_id": uuid4().hex,
        "case_id": case_id,
        "artifact_type": artifact_type,
        "classification": classification,
        "content_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        "payload": payload,
        "created_at": datetime.now(UTC).isoformat(),
        "chain_of_custody": [
            {
                "actor": "ares",
                "action": "artifact_created",
                "timestamp": datetime.now(UTC).isoformat(),
            }
        ],
    }
