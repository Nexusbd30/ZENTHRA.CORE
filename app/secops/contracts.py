from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

DevSecOpsEventType = Literal[
    "sast_finding",
    "dependency_vuln",
    "secret_leak",
    "container_vuln",
    "iac_misconfig",
    "deployment_anomaly",
    "pipeline_identity_risk",
]


class DevSecOpsSignal(BaseModel):
    provider: str = Field(..., min_length=1)
    event_id: str = Field(..., min_length=1)
    event_type: DevSecOpsEventType | str = Field(..., min_length=1)
    pipeline_id: str | None = None
    run_id: str | None = None
    repository: str | None = None
    branch: str | None = None
    commit_sha: str | None = None
    artifact: str | None = None
    environment: str | None = None
    actor_identity: str | None = None
    occurred_at: datetime | None = None
    severity: int = Field(default=5, ge=1, le=10)
    finding_count: int = Field(default=1, ge=0)
    critical_count: int = Field(default=0, ge=0)
    high_count: int = Field(default=0, ge=0)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cve_ids: list[str] = Field(default_factory=list)
    secret_detected: bool = False
    privileged_actor: bool = False
    production_target: bool = False
    deployment_blocked: bool = False
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class DevSecOpsLifecycleRequest(BaseModel):
    signal: DevSecOpsSignal
    execution_controls: dict[str, Any] = Field(default_factory=lambda: {"dry_run": True})
    human_approved: bool = False
    approval_evidence: dict[str, Any] | None = None


class DevSecOpsSignalIngestResponse(BaseModel):
    status: str
    event_id: str
    source_event_id: str
    source: str
    event_type: str
    entity_id: str
    entity_type: str
    severity: int
    risk_score: float
    mitre_tags: list[str]
    signals: list[str]
    is_duplicate: bool
    processing_time_ms: float


class DevSecOpsSignalSummaryResponse(BaseModel):
    module: str
    count: int
    max_risk_score: float
    risk_level: str
    event_types: list[str]
    providers: list[str]
    repositories: list[str]
    environments: list[str]
    signals: list[str]


class DevSecOpsIdentityCorrelationResponse(BaseModel):
    module: str
    actor_identity: str
    identity_entity_id: str
    correlated: bool
    correlation_score: float
    risk_level: str
    identity_activity: dict[str, Any]
    devsecops_summary: dict[str, Any]
    signals: list[str]
    recommended_action: str


class DevSecOpsCorrelationLifecycleRequest(BaseModel):
    execution_controls: dict[str, Any] = Field(default_factory=lambda: {"dry_run": True})
    human_approved: bool = False
    approval_evidence: dict[str, Any] | None = None


class DevSecOpsCorrelationMaterializeRequest(BaseModel):
    min_score: float = Field(default=60.0, ge=0.0, le=100.0)
    limit: int = Field(default=100, ge=1, le=500)


class DevSecOpsCorrelationMaterializeResponse(BaseModel):
    module: str
    scanned_actors: int
    materialized: int
    duplicates: int
    skipped: int
    min_score: float
    items: list[dict[str, Any]]


class DevSecOpsProviderPreflightRequest(BaseModel):
    action_type: str = Field(..., min_length=1)
    execution_controls: dict[str, Any] = Field(default_factory=dict)


class SecOpsExecutionPreflightRequest(BaseModel):
    provider: str = Field(..., min_length=1)
    action_type: str = Field(..., min_length=1)
    execution_controls: dict[str, Any] = Field(default_factory=dict)


class DevSecOpsProviderCapabilitiesResponse(BaseModel):
    provider: str
    commands: list[str]
    actions: list[str]
    supports_webhook_bridge: bool
    notes: str


class DevSecOpsProviderPreflightResponse(BaseModel):
    provider: str
    action_type: str
    supported: bool
    recommended_action: str
    adjusted: bool
    supported_actions: list[str]
    reason: str


class SecOpsReadinessResponse(BaseModel):
    integration: str | None = None
    module: str | None = None
    status: str | None = None
    overall: str | None = None
    configured: bool | None = None
    secrets_exposed: bool = False


class SecOpsExecutionPreflightResponse(BaseModel):
    provider: str
    action_type: str
    mode: str
    allowed: bool
    checks: dict[str, bool]
    provider_preflight: dict[str, Any]
    readiness: dict[str, Any]
    reason: str
    secrets_exposed: bool = False


class DevSecOpsControl(BaseModel):
    key: str
    status: str
    owner: str
    detail: str


class SecOpsPostureResponse(BaseModel):
    module: str
    mode: str
    overall: str
    identity_events: int
    devsecops_events: int
    correlation_events: int
    security_events: int
    security_event_summary: dict[str, Any]
    open_verdicts: int
    failed_executions: int
    audit_records: int
    provider_registry: dict[str, Any]
    controls: list[DevSecOpsControl]


class SecOpsStatusResponse(BaseModel):
    module: str
    role: str
    phase: str
    integrates: list[str]
    devsecops_controls: list[str]


class SecurityEventItem(BaseModel):
    record_id: str
    timestamp: datetime
    event_type: str
    reason: str
    status_code: int
    provider: str
    source: str
    source_event_id: str
    tenant_id: str
    capability: str
    client_ip: str
    payload_sha256: str
    secrets_exposed: bool = False


class SecurityEventSummaryResponse(BaseModel):
    module: str
    count: int
    limit: int
    filters: dict[str, Any]
    by_reason: dict[str, int]
    by_provider: dict[str, int]
    by_tenant: dict[str, int]
    items: list[SecurityEventItem]


class SecurityEventMaterializeRequest(BaseModel):
    min_count: int = Field(default=2, ge=1, le=100)
    limit: int = Field(default=100, ge=1, le=500)


class SecurityEventMaterializeResponse(BaseModel):
    module: str
    scanned_events: int
    scanned_groups: int
    materialized: int
    duplicates: int
    skipped: int
    min_count: int
    items: list[dict[str, Any]]


class SecurityEventLifecycleRequest(BaseModel):
    execution_controls: dict[str, Any] = Field(default_factory=lambda: {"dry_run": True})
    human_approved: bool = False
    approval_evidence: dict[str, Any] | None = None


class SecurityEventExportRequest(BaseModel):
    destination: str = Field(default="generic_webhook", min_length=1)
    format: str = Field(default="soc_case.v1", min_length=1)
    include_items: bool = True
    send: bool = False
    limit: int = Field(default=100, ge=1, le=500)
    reason: str | None = None
    tenant_id: str | None = None


class SecurityEventExportResponse(BaseModel):
    module: str
    contract: str
    destination: str
    ready_to_send: bool
    count: int
    payload: dict[str, Any]
    delivery: dict[str, Any] | None = None
    secrets_exposed: bool = False


class IntelligenceStatusResponse(BaseModel):
    module: str
    mode: str
    rag: dict[str, Any]
    llm: dict[str, Any]
    mcp: dict[str, Any]
    domains: list[str]
    recommended_actions: list[str]
