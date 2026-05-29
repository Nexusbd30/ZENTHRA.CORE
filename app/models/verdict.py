from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Verdict(Base):
    __tablename__ = "verdicts"

    verdict_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    threat_event_id: Mapped[str] = mapped_column(String(36), default="", index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    severity: Mapped[str] = mapped_column(String(32), default="medium")
    target: Mapped[str] = mapped_column(String(128), index=True)
    action_type: Mapped[str] = mapped_column(String(64), index=True)
    recommended_actions: Mapped[str] = mapped_column(Text, default="[]")
    primary_action: Mapped[str] = mapped_column(String(64), default="")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    factors: Mapped[str] = mapped_column(Text, default="[]")
    xai_explanation: Mapped[str] = mapped_column(Text, default="{}")
    justification_xai: Mapped[str] = mapped_column(Text, default="")
    policy_check: Mapped[bool] = mapped_column(Boolean, default=False)
    requires_human: Mapped[bool] = mapped_column(Boolean, default=False)
    requires_human_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    policy_rule: Mapped[str] = mapped_column(String(255), default="")
    ttl_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    execution_controls: Mapped[str] = mapped_column(Text, default="{}")
    signature: Mapped[str] = mapped_column(String(128), default="")
