from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from app.models.threat_model import ThreatCategory, ThreatLevel

SEVERITY_TO_LEVEL = {
    "critical": ThreatLevel.critical,
    "high": ThreatLevel.high,
    "warning": ThreatLevel.medium,
    "medium": ThreatLevel.medium,
    "low": ThreatLevel.low,
    "info": ThreatLevel.low,
    "informational": ThreatLevel.low,
}

CATEGORY_HINTS = {
    "auth": ThreatCategory.auth,
    "iam": ThreatCategory.auth,
    "identity": ThreatCategory.auth,
    "database": ThreatCategory.database,
    "db": ThreatCategory.database,
    "network": ThreatCategory.network,
    "netflow": ThreatCategory.network,
    "availability": ThreatCategory.availability,
    "performance": ThreatCategory.performance,
    "edr": ThreatCategory.other,
}

LEVEL_SCORE = {
    ThreatLevel.critical: 95,
    ThreatLevel.high: 82,
    ThreatLevel.medium: 62,
    ThreatLevel.low: 35,
}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _hash(parts: list[str]) -> str:
    joined = "|".join(part for part in parts if part)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def normalize_event(raw_event: dict[str, Any]) -> dict[str, Any]:
    labels = _dict(raw_event.get("labels"))
    annotations = _dict(raw_event.get("annotations"))
    event = _dict(raw_event.get("event"))
    source = _str(raw_event.get("source") or event.get("source") or labels.get("job"), "siem/ingestion")

    alertname = _str(
        raw_event.get("alertname")
        or labels.get("alertname")
        or event.get("alertname")
        or event.get("rule")
        or raw_event.get("title"),
        "SecurityEvent",
    )
    target = _str(
        raw_event.get("target")
        or raw_event.get("target_service")
        or labels.get("service")
        or labels.get("instance")
        or event.get("host")
        or event.get("user")
        or event.get("asset"),
        "unknown-target",
    )
    source_ip = _str(raw_event.get("source_ip") or event.get("source_ip") or labels.get("source_ip"), "")
    severity = _str(raw_event.get("severity") or labels.get("severity") or event.get("severity"), "medium").lower()
    level = SEVERITY_TO_LEVEL.get(severity, ThreatLevel.medium)
    category_hint = _str(raw_event.get("category") or event.get("category") or source, "other").lower()
    category = next(
        (mapped for hint, mapped in CATEGORY_HINTS.items() if hint in category_hint),
        ThreatCategory.other,
    )
    score = raw_event.get("score")
    try:
        score_int = max(0, min(100, int(score))) if score is not None else LEVEL_SCORE[level]
    except (TypeError, ValueError):
        score_int = LEVEL_SCORE[level]

    fingerprint = _str(raw_event.get("fingerprint"), "")
    if not fingerprint:
        fingerprint = _hash([source, alertname, target, source_ip, category.value])

    first_seen_at = _str(raw_event.get("first_seen_at") or event.get("first_seen_at"), _now_iso())
    last_seen_at = _str(raw_event.get("last_seen_at") or event.get("last_seen_at"), first_seen_at)
    description = _str(
        raw_event.get("description")
        or annotations.get("description")
        or annotations.get("summary")
        or event.get("message"),
        f"{alertname} detected on {target}",
    )

    return {
        "title": _str(raw_event.get("title"), alertname),
        "source": source,
        "description": description,
        "level": level,
        "category": category,
        "score": score_int,
        "target_service": target,
        "source_ip": source_ip or None,
        "database_name": raw_event.get("database_name") or event.get("database_name"),
        "database_host": raw_event.get("database_host") or event.get("database_host"),
        "fingerprint": fingerprint,
        "siem_metadata": {
            "status": _str(raw_event.get("status"), "open"),
            "first_seen_at": first_seen_at,
            "last_seen_at": last_seen_at,
            "occurrences": 1,
            "evidence": {
                "labels": labels,
                "annotations": annotations,
                "event": event,
                "state": _str(raw_event.get("state") or event.get("state"), "firing"),
                "value": _str(raw_event.get("value") or event.get("value"), "1"),
                "raw": raw_event,
            },
        },
    }
