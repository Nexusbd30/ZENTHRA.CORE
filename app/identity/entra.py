from __future__ import annotations

import hashlib
import hmac
import time
from datetime import UTC, datetime
from typing import Any

from app.core.secrets import get_secret
from app.core.settings import settings
from app.identity.contracts import IdentitySignal

ENTRA_RISK_EVENT_MAP = {
    "tokenreplay": "token_reuse",
    "impossibletravel": "impossible_travel",
    "suspiciousconsent": "suspicious_consent",
    "mcapolicyfailure": "mfa_bypass",
    "anonymizedipaddress": "session_anomaly",
    "unfamiliarfeatures": "session_anomaly",
    "passwordspray": "credential_attack",
    "leakedcredentials": "credential_attack",
    "maliciousipaddress": "identity_compromise",
}

RISK_LEVEL_SEVERITY = {
    "low": 4,
    "medium": 6,
    "high": 8,
    "hidden": 5,
    "none": 3,
}


def _compact(value: Any) -> str:
    return str(value or "").strip()


def _event_type(raw_type: str) -> str:
    normalized = _compact(raw_type).replace("_", "").replace("-", "").lower()
    return ENTRA_RISK_EVENT_MAP.get(normalized, "session_anomaly")


def _severity(payload: dict[str, Any]) -> int:
    risk_level = _compact(payload.get("riskLevel")).lower()
    base = RISK_LEVEL_SEVERITY.get(risk_level, 5)
    if bool(payload.get("isPrivileged")):
        base += 1
    if _compact(payload.get("riskState")).lower() in {"confirmedcompromised", "at_risk"}:
        base += 1
    return max(1, min(10, base))


def _occurred_at(payload: dict[str, Any]) -> datetime | None:
    raw = _compact(payload.get("createdDateTime") or payload.get("activityDateTime"))
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _location(payload: dict[str, Any]) -> tuple[str | None, str | None]:
    location = payload.get("location")
    if not isinstance(location, dict):
        return None, None
    country = _compact(location.get("countryOrRegion")) or None
    city = _compact(location.get("city")) or None
    return country, city


def normalize_entra_risk_event(payload: dict[str, Any]) -> IdentitySignal:
    risk_event_type = _compact(payload.get("riskEventType") or payload.get("event_type"))
    user_principal = _compact(
        payload.get("userPrincipalName")
        or payload.get("user_principal_name")
        or payload.get("identity_id")
        or payload.get("userId")
    )
    country, city = _location(payload)
    event_type = _event_type(risk_event_type)
    return IdentitySignal(
        provider="entra",
        event_id=_compact(payload.get("id") or payload.get("event_id")),
        event_type=event_type,
        identity_id=user_principal,
        occurred_at=_occurred_at(payload),
        severity=_severity(payload),
        ip_address=_compact(payload.get("ipAddress")) or None,
        geo_country=country,
        geo_city=city,
        device_id=_compact(payload.get("deviceId")) or None,
        user_agent=_compact(payload.get("userAgent")) or None,
        mfa_present=bool(payload.get("mfaSatisfied")) if "mfaSatisfied" in payload else None,
        privileged=bool(payload.get("isPrivileged")),
        impossible_travel=event_type == "impossible_travel",
        token_reuse=event_type == "token_reuse",
        raw_payload=payload,
    )


def expected_entra_signature(body: bytes, secret: str, timestamp: str | None = None) -> str:
    signed_payload = body if not timestamp else f"{timestamp}.".encode("utf-8") + body
    digest = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def entra_replay_key(*, body: bytes, signature: str | None, timestamp: str | None) -> str:
    payload = "|".join(
        [
            _compact(timestamp),
            _compact(signature),
            hashlib.sha256(body).hexdigest(),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _timestamp_is_fresh(timestamp: str | None) -> bool:
    if not timestamp:
        return False
    try:
        received_at = float(timestamp)
    except ValueError:
        return False
    max_skew = max(1, int(settings.ENTRA_WEBHOOK_MAX_SKEW_SEC))
    return abs(time.time() - received_at) <= max_skew


def verify_entra_webhook_signature(
    body: bytes,
    signature: str | None,
    timestamp: str | None,
) -> bool:
    secret = get_secret("ENTRA_WEBHOOK_SECRET", settings.ENTRA_WEBHOOK_SECRET)
    if not secret:
        return True
    if not signature or not _timestamp_is_fresh(timestamp):
        return False
    compact_timestamp = _compact(timestamp)
    expected = expected_entra_signature(body, secret, compact_timestamp)
    provided = _compact(signature)
    if not provided.startswith("sha256="):
        provided = f"sha256={provided}"
    return hmac.compare_digest(provided, expected)


def build_entra_provider_evidence(
    *,
    payload: dict[str, Any],
    body: bytes,
    timestamp: str | None,
) -> dict[str, Any]:
    source_event_id = _compact(payload.get("id") or payload.get("event_id"))
    payload_sha256 = hashlib.sha256(body).hexdigest()
    return {
        "kind": "identity_provider_webhook",
        "provider": "entra",
        "source": "identity:entra",
        "source_event_id": source_event_id,
        "received_via": "signed_webhook",
        "received_at": datetime.now(UTC).isoformat(),
        "payload_sha256": payload_sha256,
        "signature": {
            "verified": bool(get_secret("ENTRA_WEBHOOK_SECRET", settings.ENTRA_WEBHOOK_SECRET)),
            "algorithm": "hmac-sha256",
            "timestamp": _compact(timestamp),
            "timestamp_header": "X-Vaelqorix-Timestamp",
            "signature_header": "X-Vaelqorix-Signature",
            "signed_payload": "timestamp.body",
            "max_skew_seconds": settings.ENTRA_WEBHOOK_MAX_SKEW_SEC,
        },
        "evidence_refs": [
            f"identity:entra:{source_event_id}" if source_event_id else "identity:entra",
            f"sha256:{payload_sha256}",
        ],
        "secrets_exposed": False,
    }


def build_entra_readiness() -> dict[str, Any]:
    client_secret = get_secret("ENTRA_CLIENT_SECRET", settings.ENTRA_CLIENT_SECRET)
    webhook_secret = get_secret("ENTRA_WEBHOOK_SECRET", settings.ENTRA_WEBHOOK_SECRET)
    has_graph_credentials = all(
        [
            settings.ENTRA_TENANT_ID,
            settings.ENTRA_CLIENT_ID,
            client_secret,
        ]
    )
    has_webhook_secret = bool(webhook_secret)
    graph_enabled = bool(settings.ENTRA_GRAPH_ENABLED and has_graph_credentials)
    graph_actions = {
        "resolve": graph_enabled,
        "disable_credentials": graph_enabled,
        "revoke_sessions": graph_enabled,
        "require_mfa": graph_enabled and bool(settings.ENTRA_REQUIRE_MFA_POLICY_URL),
        "degrade_privileges": graph_enabled
        and bool(str(settings.ENTRA_DEGRADE_PRIVILEGES_GROUP_IDS or "").strip()),
    }
    return {
        "provider": "entra",
        "mode": "graph_and_webhook" if graph_enabled else "webhook_normalization",
        "configured": bool(has_graph_credentials or has_webhook_secret),
        "graph_enabled": graph_enabled,
        "graph_credentials_configured": bool(has_graph_credentials),
        "graph": {
            "enabled": graph_enabled,
            "base_url": settings.ENTRA_GRAPH_BASE_URL,
            "token_url_configured": bool(settings.ENTRA_GRAPH_TOKEN_URL),
            "actions": graph_actions,
            "least_privilege_notes": [
                "User.Read.All for identity.resolve",
                "User.EnableDisableAccount.All or equivalent for disable_credentials",
                "User.RevokeSessions.All for revoke_sessions",
                "Conditional Access or governance bridge required for require_mfa",
                "GroupMember.ReadWrite.All scoped to approved groups for degrade_privileges",
            ],
        },
        "webhook_secret_configured": has_webhook_secret,
        "supported_inputs": [
            "identity_protection_risk_event",
            "sentinel_entra_identity_alert",
            "generic_entra_webhook",
        ],
        "normalizes_to": "identity_signal.v1",
        "provider_evidence": {
            "persisted": True,
            "location": "ThreatEvent.normalized_payload.provider_evidence",
            "hash": "payload_sha256",
        },
        "rate_limit": {
            "enabled": settings.ENTRA_WEBHOOK_RATE_LIMIT_ENABLED,
            "requests": settings.ENTRA_WEBHOOK_RATE_LIMIT_REQUESTS,
            "window_seconds": settings.ENTRA_WEBHOOK_RATE_LIMIT_WINDOW_SEC,
            "scope": "tenant_id + client_ip + provider",
        },
        "replay_guard": {
            "enabled": settings.ENTRA_WEBHOOK_REPLAY_GUARD_ENABLED,
            "ttl_seconds": settings.ENTRA_WEBHOOK_REPLAY_TTL_SEC,
            "scope": "timestamp + signature + payload_sha256",
            "backend": "in_memory",
        },
        "signature": {
            "required": has_webhook_secret,
            "algorithm": "hmac-sha256",
            "header": "X-Vaelqorix-Signature",
            "timestamp_header": "X-Vaelqorix-Timestamp",
            "max_skew_seconds": settings.ENTRA_WEBHOOK_MAX_SKEW_SEC,
        },
        "secrets_exposed": False,
        "next_step": (
            "connect_entra_or_sentinel_webhook_source"
            if has_webhook_secret
            else "configure_ENTRA_WEBHOOK_SECRET_or_graph_credentials"
        ),
    }
