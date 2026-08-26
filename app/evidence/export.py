from __future__ import annotations

from typing import Any


def export_evidence_json(*, case_payload: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "vaelqorix.evidence.export.v1",
        "format": "json",
        "case": case_payload,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "export_boundaries": [
            "no_secret_values",
            "hash_payloads",
            "preserve_chain_of_custody",
        ],
    }
