from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class VectorEntry(Base):
    __tablename__ = "vector_entries"
    __table_args__ = (UniqueConstraint("tenant_id", "collection", "record_id", name="uq_vector_record"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    collection: Mapped[str] = mapped_column(String(120), index=True)
    record_id: Mapped[str] = mapped_column(String(255))
    vector_json: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[str] = mapped_column(Text)


class RuntimeJob(Base):
    __tablename__ = "runtime_jobs"
    __table_args__ = (UniqueConstraint("tenant_id", "queue", "idempotency_key", name="uq_runtime_job_key"),)
    job_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    queue: Mapped[str] = mapped_column(String(120), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(255))
    payload_json: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    queued_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    lease_token: Mapped[str] = mapped_column(String(36), default="")
    error: Mapped[str] = mapped_column(Text, default="")
