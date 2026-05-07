from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.core.signing import sign_payload, verify_payload_signature


def build_approval_payload(
    *,
    verdict: dict[str, Any],
    approver: str,
    reason: str = "",
) -> dict[str, Any]:
    payload = {
        "verdict_id": str(verdict.get("verdict_id") or ""),
        "target": str(verdict.get("target") or ""),
        "action_type": str(verdict.get("action_type") or ""),
        "risk_score": float(verdict.get("risk_score", 0.0) or 0.0),
        "approved": True,
        "approver": approver.strip(),
        "reason": reason.strip(),
        "approved_at": datetime.now(UTC).isoformat(),
    }
    payload["signature"] = sign_payload(payload)
    return payload


def verify_approval_payload(
    *,
    verdict: dict[str, Any],
    approval: dict[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(approval, dict):
        return {
            "valid": False,
            "code": "approval_missing",
            "detail": "Human approval evidence is required",
        }

    signature = approval.get("signature")
    if not isinstance(signature, str) or not signature:
        return {
            "valid": False,
            "code": "approval_signature_missing",
            "detail": "Human approval signature is required",
        }

    payload = {key: value for key, value in approval.items() if key != "signature"}
    if not verify_payload_signature(payload, signature):
        return {
            "valid": False,
            "code": "approval_signature_invalid",
            "detail": "Human approval signature is invalid",
        }

    expected = {
        "verdict_id": str(verdict.get("verdict_id") or ""),
        "target": str(verdict.get("target") or ""),
        "action_type": str(verdict.get("action_type") or ""),
        "risk_score": float(verdict.get("risk_score", 0.0) or 0.0),
    }
    for key, value in expected.items():
        if approval.get(key) != value:
            return {
                "valid": False,
                "code": "approval_verdict_mismatch",
                "detail": f"Human approval does not match verdict field '{key}'",
            }

    if approval.get("approved") is not True:
        return {
            "valid": False,
            "code": "approval_not_granted",
            "detail": "Human approval evidence is not granted",
        }

    if not str(approval.get("approver") or "").strip():
        return {
            "valid": False,
            "code": "approval_approver_missing",
            "detail": "Human approver identity is required",
        }

    return {"valid": True, "code": "ok", "detail": "approved"}
