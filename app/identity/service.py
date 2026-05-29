from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.identity.contracts import IdentitySignal
from app.identity.providers import strongest_supported_identity_action
from app.models.threat_event import ThreatEvent

IDENTITY_MITRE_MAP: dict[str, list[str]] = {
    "login_failure": ["T1110"],
    "credential_attack": ["T1110", "T1078"],
    "identity_compromise": ["T1078"],
    "impossible_travel": ["T1078"],
    "token_reuse": ["T1528", "T1078"],
    "mfa_bypass": ["T1556", "T1078"],
    "privilege_escalation": ["T1078"],
    "suspicious_consent": ["T1528"],
    "session_anomaly": ["T1078"],
}


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _source(provider: str) -> str:
    return f"identity:{provider.strip().lower()}"


def _risk_score(signal: IdentitySignal) -> float:
    score = float(signal.severity) * 8.0
    if signal.privileged:
        score += 14.0
    if signal.impossible_travel:
        score += 18.0
    if signal.token_reuse:
        score += 18.0
    if signal.mfa_present is False:
        score += 10.0
    if signal.event_type in {"mfa_bypass", "privilege_escalation", "identity_compromise"}:
        score += 16.0
    if signal.event_type in {"credential_attack", "suspicious_consent"}:
        score += 10.0
    return round(max(0.0, min(100.0, score)), 2)


def _identity_context(signal: IdentitySignal, *, event_type: str, risk_score: float) -> dict[str, Any]:
    signals: list[str] = []
    if signal.privileged:
        signals.append("privileged_identity")
    if signal.impossible_travel:
        signals.append("impossible_travel")
    if signal.token_reuse:
        signals.append("token_reuse")
    if signal.mfa_present is False:
        signals.append("mfa_absent")
    if signal.mfa_present is True:
        signals.append("mfa_present")

    location_parts = [item for item in [signal.geo_city, signal.geo_country] if item]
    location = ", ".join(location_parts)
    summary_parts = [
        f"{event_type} for {signal.identity_id}",
        f"provider={signal.provider}",
        f"risk={risk_score}",
    ]
    if signals:
        summary_parts.append("signals=" + ",".join(signals))
    if location:
        summary_parts.append(f"location={location}")

    return {
        "subject": {
            "identity_id": signal.identity_id,
            "provider": signal.provider,
            "privileged": signal.privileged,
        },
        "session": {
            "ip_address": signal.ip_address,
            "device_id": signal.device_id,
            "user_agent": signal.user_agent,
            "mfa_present": signal.mfa_present,
        },
        "geo": {
            "country": signal.geo_country,
            "city": signal.geo_city,
        },
        "signals": signals,
        "summary": "; ".join(summary_parts),
    }


def _provider_evidence(signal: IdentitySignal) -> dict[str, Any]:
    if signal.provider_evidence:
        return dict(signal.provider_evidence)
    raw_payload_hash = ""
    if signal.raw_payload:
        raw_payload_hash = hashlib.sha256(_json(signal.raw_payload).encode("utf-8")).hexdigest()
    refs = [f"identity:{signal.provider}:{signal.event_id}"]
    if raw_payload_hash:
        refs.append(f"sha256:{raw_payload_hash}")
    return {
        "kind": "identity_signal",
        "provider": signal.provider,
        "source": _source(str(signal.provider)),
        "source_event_id": signal.event_id,
        "received_via": "identity_signal_api",
        "payload_sha256": raw_payload_hash,
        "evidence_refs": refs,
        "secrets_exposed": False,
    }


def canonicalize_identity_signal(signal: IdentitySignal) -> dict[str, Any]:
    event_type = str(signal.event_type).strip().lower()
    mitre_tags = sorted(set(IDENTITY_MITRE_MAP.get(event_type, ["T1078"])))
    risk_score = _risk_score(signal)
    identity_context = _identity_context(signal, event_type=event_type, risk_score=risk_score)
    provider_evidence = _provider_evidence(signal)
    normalized = {
        "contract": "identity_signal.v1",
        "provider": signal.provider,
        "event_type": event_type,
        "identity_id": signal.identity_id,
        "ip_address": signal.ip_address,
        "device_id": signal.device_id,
        "user_agent": signal.user_agent,
        "mfa_present": signal.mfa_present,
        "privileged": signal.privileged,
        "impossible_travel": signal.impossible_travel,
        "token_reuse": signal.token_reuse,
        "risk_score": risk_score,
        "identity_context": identity_context,
        "provider_evidence": provider_evidence,
        "evidence_refs": provider_evidence.get("evidence_refs", []),
    }
    return {
        "source": _source(str(signal.provider)),
        "event_id": signal.event_id,
        "occurred_at": signal.occurred_at,
        "event_type": event_type,
        "severity": signal.severity,
        "entity_id": f"user:{signal.identity_id}",
        "entity_type": "user",
        "mitre_tags": mitre_tags,
        "raw_payload": signal.raw_payload,
        "normalized_payload": normalized,
        "src_ip": signal.ip_address or "",
        "dst_ip": "",
        "src_port": None,
        "dst_port": None,
        "geo_country": signal.geo_country or "",
        "geo_city": signal.geo_city or "",
        "risk_score": risk_score,
    }


def persist_identity_event(db: Session, signal: IdentitySignal) -> tuple[ThreatEvent, bool]:
    canonical = canonicalize_identity_signal(signal)
    existing = db.scalar(
        select(ThreatEvent).where(
            ThreatEvent.source == canonical["source"],
            ThreatEvent.event_id == canonical["event_id"],
        )
    )
    if existing:
        return existing, True

    now = datetime.now(UTC).replace(tzinfo=None)
    occurred_at = canonical["occurred_at"]
    if isinstance(occurred_at, datetime) and occurred_at.tzinfo is not None:
        occurred_at = occurred_at.astimezone(UTC).replace(tzinfo=None)

    event = ThreatEvent(
        source=canonical["source"],
        event_id=canonical["event_id"],
        occurred_at=occurred_at,
        ingested_at=now,
        timestamp=occurred_at or now,
        event_type=canonical["event_type"],
        severity=canonical["severity"],
        entity_id=canonical["entity_id"],
        entity_type=canonical["entity_type"],
        mitre_tags=_json(canonical["mitre_tags"]),
        raw_payload=_json(canonical["raw_payload"]),
        normalized=_json(canonical["normalized_payload"]),
        normalized_payload=_json(canonical["normalized_payload"]),
        src_ip=canonical["src_ip"],
        dst_ip=canonical["dst_ip"],
        src_port=canonical["src_port"],
        dst_port=canonical["dst_port"],
        geo_country=canonical["geo_country"],
        geo_city=canonical["geo_city"],
        risk_score=canonical["risk_score"],
        is_duplicate=False,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event, False


def summarize_identity_activity(db: Session, *, entity_id: str, limit: int = 10) -> dict[str, Any]:
    rows = list(
        db.scalars(
            select(ThreatEvent)
            .where(ThreatEvent.entity_id == entity_id)
            .where(ThreatEvent.entity_type == "user")
            .order_by(ThreatEvent.timestamp.desc())
            .limit(max(1, min(limit, 50)))
        ).all()
    )

    event_types: list[str] = []
    providers: list[str] = []
    signals: list[str] = []
    max_risk_score = 0.0
    for row in rows:
        event_types.append(str(row.event_type))
        max_risk_score = max(max_risk_score, float(row.risk_score or 0.0))
        try:
            normalized = json.loads(row.normalized_payload or row.normalized or "{}")
        except json.JSONDecodeError:
            normalized = {}
        provider = normalized.get("provider")
        if provider:
            providers.append(str(provider))
        identity_context = normalized.get("identity_context")
        if isinstance(identity_context, dict):
            context_signals = identity_context.get("signals")
            if isinstance(context_signals, list):
                signals.extend(str(item) for item in context_signals if item)

    distinct_providers = sorted(set(providers))
    recommended_provider = distinct_providers[0] if len(distinct_providers) == 1 else ""
    if max_risk_score >= 82:
        risk_level = "critical"
    elif max_risk_score >= 60:
        risk_level = "high"
    elif max_risk_score >= 35:
        risk_level = "medium"
    else:
        risk_level = "low"

    recommended_action = (
        strongest_supported_identity_action(recommended_provider, max_risk_score)
        if recommended_provider
        else "soar_delegate"
    )

    return {
        "entity_id": entity_id,
        "event_count": len(rows),
        "event_types": sorted(set(event_types)),
        "signals": sorted(set(signals)),
        "providers": distinct_providers,
        "max_risk_score": round(max_risk_score, 2),
        "risk_level": risk_level,
        "recommended_action": recommended_action,
        "recommended_provider": recommended_provider,
    }


def list_identity_event_timeline(db: Session, *, entity_id: str, limit: int = 20) -> dict[str, Any]:
    rows = list(
        db.scalars(
            select(ThreatEvent)
            .where(ThreatEvent.entity_id == entity_id)
            .where(ThreatEvent.entity_type == "user")
            .order_by(ThreatEvent.timestamp.desc())
            .limit(max(1, min(limit, 100)))
        ).all()
    )
    items: list[dict[str, Any]] = []
    for row in rows:
        try:
            mitre_tags = json.loads(row.mitre_tags or "[]")
        except json.JSONDecodeError:
            mitre_tags = []
        try:
            normalized = json.loads(row.normalized_payload or row.normalized or "{}")
        except json.JSONDecodeError:
            normalized = {}
        identity_context = normalized.get("identity_context")
        context = identity_context if isinstance(identity_context, dict) else {}
        raw_signals = context.get("signals")
        signals = raw_signals if isinstance(raw_signals, list) else []
        items.append(
            {
                "id": row.id,
                "source_event_id": row.event_id,
                "source": row.source,
                "event_type": row.event_type,
                "severity": row.severity,
                "risk_score": row.risk_score,
                "occurred_at": row.occurred_at,
                "ingested_at": row.ingested_at,
                "mitre_tags": [str(item) for item in mitre_tags],
                "signals": [str(item) for item in signals],
                "provider": str(normalized.get("provider") or ""),
                "summary": str(context.get("summary") or ""),
            }
        )
    return {
        "entity_id": entity_id,
        "count": len(items),
        "items": items,
    }
