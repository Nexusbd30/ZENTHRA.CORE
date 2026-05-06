from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.verdict import Verdict


class VerdictRepository:
    @staticmethod
    def create(db: Session, verdict: Verdict) -> Verdict:
        db.add(verdict)
        db.commit()
        db.refresh(verdict)
        return verdict

    @staticmethod
    def get_by_id(db: Session, verdict_id: str) -> Verdict | None:
        return db.query(Verdict).filter(Verdict.verdict_id == verdict_id).first()
