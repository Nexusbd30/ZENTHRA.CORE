from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Verdict(Base):
    __tablename__ = "verdicts"

    verdict_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    target: Mapped[str] = mapped_column(String(128), index=True)
    action_type: Mapped[str] = mapped_column(String(64), index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    factors: Mapped[str] = mapped_column(Text, default="[]")
    justification_xai: Mapped[str] = mapped_column(Text, default="")
    policy_check: Mapped[bool] = mapped_column(Boolean, default=False)
    requires_human: Mapped[bool] = mapped_column(Boolean, default=False)
    execution_controls: Mapped[str] = mapped_column(Text, default="{}")
    signature: Mapped[str] = mapped_column(String(128), default="")
