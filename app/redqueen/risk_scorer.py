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

    try:
        occurrences = int(metadata.get("occurrences", 0) or 0)
    except (TypeError, ValueError):
        occurrences = 0

    if str(metadata.get("status", "")).lower() == "open":
        score += 3
    if occurrences >= 3:
        score += min(10, occurrences)
    if labels.get("severity") == "critical":
        score += 5
    if perception.get("source_ip"):
        score += 2
    if perception.get("database_name") or perception.get("database_host"):
        score += 5

    score = max(0.0, min(100.0, score))
    return {
        "risk_score": score,
        "scoring_model": "redqueen.rules.v1",
        "score_inputs": {
            "explicit_score": explicit_score,
            "level": perception.get("level"),
            "category": perception.get("category"),
            "status": metadata.get("status"),
            "occurrences": occurrences,
            "source_ip_present": bool(perception.get("source_ip")),
            "database_asset": bool(perception.get("database_name") or perception.get("database_host")),
        },
    }
