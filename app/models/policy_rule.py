from __future__ import annotations

import uuid

from sqlalchemy import Boolean, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class PolicyRule(Base):
    __tablename__ = "policy_rules"

    rule_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    condition_dsl: Mapped[str] = mapped_column(Text, default="")
    action_allowed: Mapped[str] = mapped_column(Text, default="[]")
    max_autonomy_score: Mapped[float] = mapped_column(Float, default=50.0)
    requires_human: Mapped[bool] = mapped_column(Boolean, default=False)
