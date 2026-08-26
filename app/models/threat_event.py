from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ThreatEvent(Base):
    __tablename__ = "threat_events"
    __table_args__ = (
        UniqueConstraint("source", "event_id", name="uq_threat_events_source_event_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    source: Mapped[str] = mapped_column(String(120), index=True)
    event_id: Mapped[str] = mapped_column(String(255), default="", index=True)
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    event_type: Mapped[str] = mapped_column(String(120), index=True)
    severity: Mapped[int] = mapped_column(Integer, default=0)
    entity_id: Mapped[str] = mapped_column(String(255), default="", index=True)
    entity_type: Mapped[str] = mapped_column(String(64), default="")
    mitre_tags: Mapped[str] = mapped_column(Text, default="[]")
    raw_payload: Mapped[str] = mapped_column(Text, default="{}")
    normalized: Mapped[str] = mapped_column(Text, default="{}")
    normalized_payload: Mapped[str] = mapped_column(Text, default="{}")
    src_ip: Mapped[str] = mapped_column(String(64), default="")
    dst_ip: Mapped[str] = mapped_column(String(64), default="")
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    geo_country: Mapped[str] = mapped_column(String(64), default="")
    geo_city: Mapped[str] = mapped_column(String(120), default="")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    is_duplicate: Mapped[bool] = mapped_column(Boolean, default=False)
