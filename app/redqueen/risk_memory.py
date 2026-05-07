from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models.entity_profile import EntityProfile
from app.models.risk_score import RiskScore
from app.repositories.risk_repository import RiskRepository


def _trend(previous: RiskScore | None, score: float) -> str:
    if previous is None:
        return "new"
    delta = score - float(previous.score_0_100)
    if delta >= 10:
        return "rising"
    if delta <= -10:
        return "falling"
    return "stable"


def record_risk_memory(db: Session, *, verdict: dict) -> dict:
    target = str(verdict.get("target") or "unknown")
    score = float(verdict.get("risk_score", 0.0) or 0.0)
    confidence = float(verdict.get("confidence", 0.0) or 0.0)
    factors = [str(item) for item in verdict.get("factors", []) if item]
    now = datetime.now(UTC)

    latest = RiskRepository.latest_scores(db, target, limit=10)
    trend = _trend(latest[0] if latest else None, score)
    row = RiskScore(
        asset_id=target,
        score_0_100=score,
        confidence=confidence,
        factors=json.dumps(factors, ensure_ascii=False),
        timestamp=now,
        trend=trend,
    )
    RiskRepository.create_score(db, row)

    baseline = [round(float(item.score_0_100), 2) for item in [row, *latest]][:10]
    profile = EntityProfile(
        entity_id=target,
        entity_type="asset",
        baseline_vector=json.dumps(baseline, ensure_ascii=False),
        anomaly_score=score,
        last_seen=now,
        risk_factors=json.dumps(factors[:20], ensure_ascii=False),
    )
    RiskRepository.upsert_profile(db, profile)

    return {
        "asset_id": target,
        "risk_score_id": row.id,
        "trend": trend,
        "baseline_vector": baseline,
    }


def read_entity_risk_memory(db: Session, *, target: str, limit: int = 10) -> dict:
    profile = RiskRepository.get_profile(db, target)
    scores = RiskRepository.latest_scores(db, target, limit=max(1, min(limit, 50)))
    return {
        "target": target,
        "profile": {
            "entity_id": profile.entity_id,
            "entity_type": profile.entity_type,
            "baseline_vector": json.loads(profile.baseline_vector or "[]"),
            "anomaly_score": profile.anomaly_score,
            "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
            "risk_factors": json.loads(profile.risk_factors or "[]"),
        }
        if profile
        else None,
        "scores": [
            {
                "id": row.id,
                "score_0_100": row.score_0_100,
                "confidence": row.confidence,
                "factors": json.loads(row.factors or "[]"),
                "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                "trend": row.trend,
            }
            for row in scores
        ],
    }
