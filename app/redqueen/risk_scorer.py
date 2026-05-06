from __future__ import annotations

from typing import Any

LEVEL_BASE = {
    "critical": 92,
    "high": 80,
    "medium": 58,
    "low": 32,
}

CATEGORY_BONUS = {
    "auth": 8,
    "database": 7,
    "network": 6,
    "availability": 4,
    "performance": 2,
    "other": 0,
}

SIGNAL_WEIGHTS = {
    "data_exfiltration": 14,
    "lateral_movement": 12,
    "privilege_escalation": 11,
    "credential_stuffing": 8,
    "bruteforce": 6,
    "malware": 10,
    "ransomware": 16,
    "endpoint_compromise": 9,
}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def score_perception(perception: dict[str, Any]) -> dict[str, Any]:
    explicit_score = perception.get("score")
    if explicit_score is not None:
        try:
            score = float(explicit_score)
        except (TypeError, ValueError):
            score = 0.0
    else:
        level = str(perception.get("level") or "medium").lower()
        category = str(perception.get("category") or "other").lower()
        score = float(LEVEL_BASE.get(level, LEVEL_BASE["medium"]))
        score += CATEGORY_BONUS.get(category, 0)

    metadata = _dict(perception.get("metadata"))
    labels = _dict(perception.get("labels"))
    annotations = _dict(perception.get("annotations"))
    siem = _dict(perception.get("siem"))

    try:
        occurrences = int(metadata.get("occurrences", 0) or 0)
    except (TypeError, ValueError):
        occurrences = 0

    if str(metadata.get("status", "")).lower() == "open":
        score += 3
    if occurrences >= 3:
        score += min(10, occurrences)
    if labels.get("severity") == "critical" or siem.get("severity") == "critical":
        score += 5
    if str(siem.get("state", "")).lower() == "firing":
        score += 3
    try:
        active_minutes = int(siem.get("active_minutes", 0) or 0)
    except (TypeError, ValueError):
        active_minutes = 0
    if active_minutes >= 60:
        score += 8
    elif active_minutes >= 15:
        score += 4
    if perception.get("source_ip"):
        score += 2
    if perception.get("database_name") or perception.get("database_host"):
        score += 5

    text = " ".join(
        str(value).lower()
        for value in [
            perception.get("title"),
            perception.get("description"),
            annotations.get("summary"),
            annotations.get("description"),
            *(perception.get("factors") or []),
        ]
        if value
    )
    matched_signals = [name for name in SIGNAL_WEIGHTS if name in text]
    score += sum(SIGNAL_WEIGHTS[name] for name in matched_signals)

    score = max(0.0, min(100.0, score))
    return {
        "risk_score": score,
        "scoring_model": "redqueen.hybrid_rules.v2",
        "score_inputs": {
            "explicit_score": explicit_score,
            "level": perception.get("level"),
            "category": perception.get("category"),
            "status": metadata.get("status"),
            "occurrences": occurrences,
            "active_minutes": active_minutes,
            "matched_signals": matched_signals,
            "source_ip_present": bool(perception.get("source_ip")),
            "database_asset": bool(perception.get("database_name") or perception.get("database_host")),
        },
    }
