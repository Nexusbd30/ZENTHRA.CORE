from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class RuntimeLogItem(BaseModel):
    timestamp: datetime
    event_id: str
    source_ip: str
    dest_ip: str
    protocol: str
    action: str
    severity: str
    message: str
    logger: str
    level: str
    status_code: int | None = None
    path: str
    request_method: str
    duration_ms: float | None = None
    source_file: str
    raw: str
    metadata: dict[str, Any]


class RuntimeLogsResponse(BaseModel):
    items: list[RuntimeLogItem]
    total: int
    files: list[str]
    generated_at: datetime


class ResponseLogRead(BaseModel):
    id: str
    timestamp: datetime
    source: str
    source_ip: str
    payload_hash: str
    payload_size: int
    alert_count: int
    status: str
    sample: str


class AiReadiness(BaseModel):
    enabled: bool
    provider: str
    model: str
    real_mode: bool


class AresReadiness(BaseModel):
    execution_mode: str
    real_mode: bool
    shared_token_configured: bool
    control_urls_configured: dict[str, bool]


class MonitoringReadiness(BaseModel):
    response_logs_persistent: bool
    alertmanager_allowed_cidrs: list[str]


class FrontendContracts(BaseModel):
    response_logs: str
    runtime_logs: str
    redqueen_verdict: str
    ares_lifecycle: str
    ares_execution_results: str


class ProductionReadinessResponse(BaseModel):
    environment: str
    status: str = Field(..., description="ready cuando no hay warnings operativos activos")
    ai: AiReadiness
    ares: AresReadiness
    monitoring: MonitoringReadiness
    frontend_contracts: FrontendContracts
    ui_rbac: dict[str, list[str]]
    warnings: list[str]


class AlertmanagerHookResponse(BaseModel):
    ok: bool
    id: str
    hash: str
    received: int
