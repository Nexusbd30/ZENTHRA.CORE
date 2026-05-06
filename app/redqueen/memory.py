from __future__ import annotations

from sqlalchemy import desc, or_, select
from sqlalchemy.orm import Session

from app.models.threat_model import ThreatModel


def recall_threat_context(
    db: Session,
    *,
    target: str | None,
    fingerprint: str | None,
    limit: int = 5,
) -> list[dict]:
    clauses = []
    if target:
        clauses.extend(
            [
                ThreatModel.target_service == target,
                ThreatModel.database_host == target,
                ThreatModel.source_ip == target,
            ]
        )
    if fingerprint:
        clauses.append(ThreatModel.fingerprint == fingerprint)

    if not clauses:
        return []

    query = (
        select(ThreatModel)
        .where(or_(*clauses))
        .order_by(desc(ThreatModel.updated_at))
        .limit(limit)
    )
    rows = db.scalars(query).all()
    return [
        {
            "id": str(row.id),
            "title": row.title,
            "level": getattr(row.level, "value", row.level),
            "score": row.score,
            "source": row.source,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }
        for row in rows
    ]
