from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuditRecord(Base):
    __tablename__ = "audit_records"

    record_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    verdict_id: Mapped[str] = mapped_column(String(36), index=True)
    hash_prev: Mapped[str] = mapped_column(String(128), default="")
    hash_self: Mapped[str] = mapped_column(String(128), default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    actor: Mapped[str] = mapped_column(String(120), default="system")
    action: Mapped[str] = mapped_column(String(120), default="")
    result: Mapped[str] = mapped_column(Text, default="{}")
