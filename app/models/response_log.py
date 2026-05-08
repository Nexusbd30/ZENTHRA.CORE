from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ResponseLog(Base):
    __tablename__ = "response_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    source: Mapped[str] = mapped_column(String(80), default="alertmanager", index=True)
    source_ip: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    payload_hash: Mapped[str] = mapped_column(String(64), index=True)
    payload_size: Mapped[int] = mapped_column(Integer, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(40), default="received", index=True)
    sample: Mapped[str] = mapped_column(Text, default="")
