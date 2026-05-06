from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ExecutionResult(Base):
    __tablename__ = "execution_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    verdict_id: Mapped[str] = mapped_column(String(36), index=True)
    ares_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(24), default="pending")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    evidence: Mapped[str] = mapped_column(Text, default="[]")
    error_code: Mapped[str] = mapped_column(String(64), default="")
    result_hash: Mapped[str] = mapped_column(String(128), default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
