from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ApprovalRecord(Base):
    __tablename__ = "approval_records"

    approval_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    verdict_id: Mapped[str] = mapped_column(String(36), index=True)
    target: Mapped[str] = mapped_column(String(255), default="")
    action_type: Mapped[str] = mapped_column(String(64), default="")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    approver: Mapped[str] = mapped_column(String(120), index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    signature: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    approved_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    recorded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
