from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.evidence.artifacts import build_evidence_artifact
from app.evidence.export import export_evidence_json


def create_case(
    *,
    title: str,
    severity: str,
    tenant_id: str,
    verdict: dict[str, Any] | None = None,
    legal_pack: dict[str, Any] | None = None,
) -> dict[str, Any]:
    case_id = uuid4().hex
    case = {
        "schema": "vaelqorix.case.v1",
        "case_id": case_id,
        "tenant_id": tenant_id,
        "title": title,
        "severity": severity,
        "status": "open",
        "created_at": datetime.now(UTC).isoformat(),
        "verdict_id": (verdict or {}).get("verdict_id", ""),
        "timeline": [
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "actor": "ares",
                "event": "case_created",
            }
        ],
        "legal_pack": legal_pack or {},
    }
    artifacts = []
    if verdict:
        artifacts.append(
            build_evidence_artifact(
                case_id=case_id,
                artifact_type="redqueen_verdict",
                payload=verdict,
            )
        )
    if legal_pack:
        artifacts.append(
            build_evidence_artifact(
                case_id=case_id,
                artifact_type="legal_escalation_pack",
                payload=legal_pack,
            )
        )
    return {"case": case, "evidence_export": export_evidence_json(case_payload=case, artifacts=artifacts)}
