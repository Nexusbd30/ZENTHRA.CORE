from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.entity_profile import EntityProfile
from app.models.risk_score import RiskScore


class RiskRepository:
    @staticmethod
    def create_score(db: Session, score: RiskScore) -> RiskScore:
        db.add(score)
        db.commit()
        db.refresh(score)
        return score

    @staticmethod
    def latest_scores(db: Session, asset_id: str, *, limit: int = 10) -> list[RiskScore]:
        return (
            db.query(RiskScore)
            .filter(RiskScore.asset_id == asset_id)
            .order_by(RiskScore.timestamp.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def upsert_profile(db: Session, profile: EntityProfile) -> EntityProfile:
        existing = db.query(EntityProfile).filter(EntityProfile.entity_id == profile.entity_id).first()
        if existing:
            existing.entity_type = profile.entity_type
            existing.baseline_vector = profile.baseline_vector
            existing.anomaly_score = profile.anomaly_score
            existing.last_seen = profile.last_seen
            existing.risk_factors = profile.risk_factors
            db.commit()
            db.refresh(existing)
            return existing
        db.add(profile)
        db.commit()
        db.refresh(profile)
        return profile

    @staticmethod
    def get_profile(db: Session, entity_id: str) -> EntityProfile | None:
        return db.query(EntityProfile).filter(EntityProfile.entity_id == entity_id).first()
