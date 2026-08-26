from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class DnsFirewallRule(Base):
    __tablename__ = "dns_firewall_rules"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "provider",
            "normalized_target",
            "status",
            name="uq_dns_firewall_active_target",
        ),
    )

    rule_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(120), index=True, default="default")
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False, default="domain")
    action: Mapped[str] = mapped_column(String(32), nullable=False, default="block")
    provider: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    verdict_id: Mapped[str] = mapped_column(String(36), index=True, default="")
    change_ticket: Mapped[str] = mapped_column(String(120), default="")
    provider_rule_id: Mapped[str] = mapped_column(String(255), default="")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(120), default="system")
    approved_by: Mapped[str] = mapped_column(String(120), default="")
    last_error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class DnsFirewallExecution(Base):
    __tablename__ = "dns_firewall_executions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_dns_firewall_idempotency"),
    )

    execution_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(120), index=True, default="default")
    rule_id: Mapped[str] = mapped_column(String(36), index=True)
    verdict_id: Mapped[str] = mapped_column(String(36), index=True, default="")
    action: Mapped[str] = mapped_column(String(32), nullable=False, default="block")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    provider_request_id: Mapped[str] = mapped_column(String(255), default="")
    evidence: Mapped[str] = mapped_column(Text, default="{}")
    error_code: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
