from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

IdentityProvider = Literal[
    "entra",
    "okta",
    "auth0",
    "keycloak",
    "github",
    "aws_iam",
    "google_workspace",
    "active_directory",
    "custom",
]

IdentityEventType = Literal[
    "login_failure",
    "login_success",
    "impossible_travel",
    "token_reuse",
    "mfa_bypass",
    "privilege_escalation",
    "suspicious_consent",
    "session_anomaly",
    "credential_attack",
    "identity_compromise",
]


class IdentitySignal(BaseModel):
    provider: IdentityProvider | str = Field(..., min_length=1)
    event_id: str = Field(..., min_length=1)
    event_type: IdentityEventType | str = Field(..., min_length=1)
    identity_id: str = Field(..., min_length=1)
    occurred_at: datetime | None = None
    severity: int = Field(default=5, ge=1, le=10)
    ip_address: str | None = None
    geo_country: str | None = None
    geo_city: str | None = None
    device_id: str | None = None
    user_agent: str | None = None
    mfa_present: bool | None = None
    privileged: bool = False
    impossible_travel: bool = False
    token_reuse: bool = False
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    provider_evidence: dict[str, Any] = Field(default_factory=dict)


class IdentityLifecycleRequest(BaseModel):
    signal: IdentitySignal
    execution_controls: dict[str, Any] = Field(default_factory=lambda: {"dry_run": True})
    human_approved: bool = False
    approval_evidence: dict[str, Any] | None = None


class IdentityTriageRequest(BaseModel):
    provider: str | None = None
    execute: bool = False
    execution_controls: dict[str, Any] = Field(default_factory=lambda: {"dry_run": True})
    human_approved: bool = False
    approval_evidence: dict[str, Any] | None = None


class IdentityProviderCapabilityRead(BaseModel):
    provider: str
    commands: list[str]
    actions: list[str]
    supports_webhook_bridge: bool = True
    notes: str = ""


class IdentityProviderListResponse(BaseModel):
    providers: list[IdentityProviderCapabilityRead]


class IdentityActionPreflightRequest(BaseModel):
    action_type: str = Field(..., min_length=1)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)


class IdentityActionPreflightResponse(BaseModel):
    provider: str
    action_type: str
    supported: bool
    recommended_action: str
    adjusted: bool
    reason: str = ""


class IdentityActivityResponse(BaseModel):
    entity_id: str
    event_count: int
    event_types: list[str]
    signals: list[str]
    providers: list[str]
    max_risk_score: float
    risk_level: str
    recommended_action: str
    recommended_provider: str = ""


class IdentityEventTimelineItem(BaseModel):
    id: str
    source_event_id: str
    source: str
    event_type: str
    severity: int
    risk_score: float
    occurred_at: datetime | None = None
    ingested_at: datetime | None = None
    mitre_tags: list[str]
    signals: list[str]
    provider: str = ""
    summary: str = ""


class IdentityEventTimelineResponse(BaseModel):
    entity_id: str
    count: int
    items: list[IdentityEventTimelineItem]
