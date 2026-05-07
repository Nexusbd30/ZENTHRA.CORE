from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.approval_record import ApprovalRecord


class ApprovalRepository:
    @staticmethod
    def create(db: Session, approval: ApprovalRecord) -> ApprovalRecord:
        existing = (
            db.query(ApprovalRecord)
            .filter(ApprovalRecord.signature == approval.signature)
            .first()
        )
        if existing:
            return existing
        db.add(approval)
        db.commit()
        db.refresh(approval)
        return approval

    @staticmethod
    def list_by_verdict(db: Session, verdict_id: str) -> list[ApprovalRecord]:
        return (
            db.query(ApprovalRecord)
            .filter(ApprovalRecord.verdict_id == verdict_id)
            .order_by(ApprovalRecord.recorded_at.desc())
            .all()
        )
