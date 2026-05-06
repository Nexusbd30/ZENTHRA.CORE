from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    source: Mapped[str] = mapped_column(String(120), index=True)
    event_type: Mapped[str] = mapped_column(String(120), index=True)
    severity: Mapped[int] = mapped_column(Integer, default=0)
    raw_payload: Mapped[str] = mapped_column(Text, default="{}")
    normalized: Mapped[str] = mapped_column(Text, default="{}")
