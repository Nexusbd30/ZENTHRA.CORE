from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

EventSource = Literal["qradar", "wazuh", "edr", "iam", "netflow", "prometheus", "manual"]
EntityType = Literal["user", "host", "service", "network", "file", "process", "unknown"]
VerdictStatus = Literal[
    "pending",
    "approved",
    "blocked",
    "executing",
    "executed",
    "rejected",
    "expired",
]
RiskLevel = Literal["low", "medium", "high", "critical"]


class AresXThreatEventCreate(BaseModel):
    source: EventSource | str
    event_id: str = Field(..., min_length=1)
    occurred_at: datetime | None = None
    event_type: str = Field(..., min_length=1)
    severity: int = Field(..., ge=1, le=10)
    entity_id: str = Field(..., min_length=1)
    entity_type: EntityType | str = "unknown"
    mitre_tags: list[str] = Field(default_factory=list)
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    normalized_payload: dict[str, Any] = Field(default_factory=dict)
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    geo_country: str | None = None
    geo_city: str | None = None


class AresXThreatEventRead(AresXThreatEventCreate):
    id: str
    ingested_at: datetime
    risk_score: float = 0.0
    is_duplicate: bool = False

    model_config = {"from_attributes": True}


class AresXRecommendedAction(BaseModel):
    action_type: str
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=1, ge=1)


class AresXVerdictCreate(BaseModel):
    threat_event_id: str
    status: VerdictStatus = "pending"
    severity: RiskLevel = "medium"
    recommended_actions: list[AresXRecommendedAction] = Field(default_factory=list)
    primary_action: str = "observe"
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    xai_explanation: dict[str, Any] = Field(default_factory=dict)
    requires_human_approval: bool = False
    policy_rule: str | None = None
    ttl_seconds: int = Field(default=3600, ge=1)


class AresXVerdictRead(AresXVerdictCreate):
    verdict_id: str
    timestamp: datetime
    expires_at: datetime | None = None

    model_config = {"from_attributes": True}


class AresXExecutionResultCreate(BaseModel):
    verdict_id: str
    action_type: str
    target_entity: str
    target_system: str = ""
    status: str = "pending"
    duration_ms: int = Field(default=0, ge=0)
    pre_state: dict[str, Any] = Field(default_factory=dict)
    post_state: dict[str, Any] = Field(default_factory=dict)
    rollback_payload: dict[str, Any] = Field(default_factory=dict)
    rl_reward: float = 0.0


class AresXExecutionResultRead(AresXExecutionResultCreate):
    id: str
    result_hash: str = ""
    timestamp: datetime

    model_config = {"from_attributes": True}


class AresXAuditRecordRead(BaseModel):
    record_id: str
    sequence_number: int | None = None
    event_type: str
    actor: str
    payload: dict[str, Any] = Field(default_factory=dict)
    content_hash: str = ""
    chain_hash: str = ""
    previous_chain_hash: str = ""
    signature: str = ""
    timestamp: datetime

    model_config = {"from_attributes": True}
