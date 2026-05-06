from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.execution_result import ExecutionResult


class ExecutionResultRepository:
    @staticmethod
    def create(db: Session, result: ExecutionResult) -> ExecutionResult:
        db.add(result)
        db.commit()
        db.refresh(result)
        return result

    @staticmethod
    def list_by_verdict(db: Session, verdict_id: str) -> list[ExecutionResult]:
        return (
            db.query(ExecutionResult)
            .filter(ExecutionResult.verdict_id == verdict_id)
            .order_by(ExecutionResult.timestamp.desc())
            .all()
        )
