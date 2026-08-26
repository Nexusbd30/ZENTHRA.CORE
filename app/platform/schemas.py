from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class PlatformDomainResponse(BaseModel):
    key: str
    name: str
    layer: str
    status: str
    responsibilities: list[str] = Field(default_factory=list)
    current_backend_mapping: list[str] = Field(default_factory=list)
    contracts: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class PlatformMapResponse(BaseModel):
    umbrella: str
    product: str
    current_core: str
    runtime: str
    migration_strategy: str
    domains: dict[str, PlatformDomainResponse]
    rules: list[str]


class PlatformReadinessCheck(BaseModel):
    name: str
    status: str
    passed: bool
    detail: str


class PlatformDomainReadiness(BaseModel):
    key: str
    name: str
    status: str
    checks: list[PlatformReadinessCheck]
    evidence: dict[str, Any] = Field(default_factory=dict)


class PlatformReadinessResponse(BaseModel):
    module: str
    product: str
    runtime: str
    overall: str
    passed: int
    failed: int
    domains: dict[str, PlatformDomainReadiness]
    next_gate: str

