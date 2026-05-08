from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class RedQueenStatusResponse(BaseModel):
    module: str
    role: str
    phase: str
    autonomy_target: int


class AresStatusResponse(BaseModel):
    module: str
    role: str
    phase: str
    kill_switch: dict[str, bool]


class PolicyEvaluationResponse(BaseModel):
    allowed: bool
    code: str
    requires_human: bool
    max_autonomy_score: float
    severity: int
    disruptive: bool
    explanation: str


class VerdictReadResponse(BaseModel):
    verdict_id: str
    timestamp: datetime
    target: str
    action_type: str
    risk_score: float
    confidence: float
    policy_check: bool
    requires_human: bool


class NotFoundResponse(BaseModel):
    status: str
    verdict_id: str | None = None
    threat_id: str | None = None


class KillSwitchResponse(BaseModel):
    status: str
    kill_switch: dict[str, bool] | None = None
    detail: str | None = None


class ExecutionResultItem(BaseModel):
    id: str
    status: str
    duration_ms: int
    error_code: str
    result_hash: str
    timestamp: datetime


class ExecutionResultsResponse(BaseModel):
    verdict_id: str
    count: int
    items: list[ExecutionResultItem]


class ApprovalItem(BaseModel):
    approval_id: str
    verdict_id: str
    target: str
    action_type: str
    risk_score: float
    approver: str
    reason: str
    signature: str
    approved_at: datetime
    recorded_at: datetime


class ApprovalListResponse(BaseModel):
    verdict_id: str
    count: int
    items: list[ApprovalItem]


class AuditItem(BaseModel):
    record_id: str
    verdict_id: str
    actor: str
    action: str
    hash_prev: str
    hash_self: str
    timestamp: datetime


class AuditListResponse(BaseModel):
    count: int
    items: list[AuditItem]


class AuditVerifyResponse(BaseModel):
    valid: bool
    count: int
    broken_at: str | None = None


class OperationFlowStep(BaseModel):
    key: str
    label: str
    endpoint: str
    owner: str
    ui_surface: str
    produces: list[str]
    requires_human: bool = False


class OperationFlowResponse(BaseModel):
    name: str
    stages: list[OperationFlowStep]
    evidence_sources: list[str]
    frontend_entrypoints: dict[str, str]
    notes: list[str]


class GenericDictResponse(BaseModel):
    data: dict[str, Any]
