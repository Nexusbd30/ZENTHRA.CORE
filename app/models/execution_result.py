from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ExecutionResult(Base):
    __tablename__ = "execution_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    verdict_id: Mapped[str] = mapped_column(String(36), index=True)
    ares_id: Mapped[str] = mapped_column(String(64), index=True)
    action_type: Mapped[str] = mapped_column(String(64), default="", index=True)
    target_entity: Mapped[str] = mapped_column(String(255), default="", index=True)
    target_system: Mapped[str] = mapped_column(String(120), default="")
    status: Mapped[str] = mapped_column(String(24), default="pending")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    pre_state: Mapped[str] = mapped_column(Text, default="{}")
    post_state: Mapped[str] = mapped_column(Text, default="{}")
    evidence: Mapped[str] = mapped_column(Text, default="[]")
    rollback_payload: Mapped[str] = mapped_column(Text, default="{}")
    rl_reward: Mapped[float] = mapped_column(Float, default=0.0)
    error_code: Mapped[str] = mapped_column(String(64), default="")
    result_hash: Mapped[str] = mapped_column(String(128), default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
