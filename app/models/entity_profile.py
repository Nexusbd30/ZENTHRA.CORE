from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class EntityProfile(Base):
    __tablename__ = "entity_profiles"

    entity_id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    entity_type: Mapped[str] = mapped_column(String(32), index=True)
    baseline_vector: Mapped[str] = mapped_column(Text, default="[]")
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    risk_factors: Mapped[str] = mapped_column(Text, default="[]")
