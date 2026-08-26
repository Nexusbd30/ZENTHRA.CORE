from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuditRecord(Base):
    __tablename__ = "audit_records"

    record_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    verdict_id: Mapped[str] = mapped_column(String(36), index=True)
    sequence_number: Mapped[int | None] = mapped_column(BigInteger, unique=True, nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(120), default="", index=True)
    hash_prev: Mapped[str] = mapped_column(String(128), default="")
    hash_self: Mapped[str] = mapped_column(String(128), default="")
    content_hash: Mapped[str] = mapped_column(String(64), default="")
    chain_hash: Mapped[str] = mapped_column(String(64), default="")
    previous_chain_hash: Mapped[str] = mapped_column(String(64), default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    actor: Mapped[str] = mapped_column(String(120), default="system")
    actor_role: Mapped[str] = mapped_column(String(64), default="system", index=True)
    tenant_id: Mapped[str] = mapped_column(String(120), default="default", index=True)
    capability: Mapped[str] = mapped_column(String(120), default="", index=True)
    request_id: Mapped[str] = mapped_column(String(120), default="")
    action: Mapped[str] = mapped_column(String(120), default="")
    payload: Mapped[str] = mapped_column(Text, default="{}")
    result: Mapped[str] = mapped_column(Text, default="{}")
    signature: Mapped[str] = mapped_column(Text, default="")
