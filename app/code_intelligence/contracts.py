from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class CodeAnalysisRequest(BaseModel):
    scope: Literal["app"] = "app"
    include_private: bool = False


class CodeComponent(BaseModel):
    module: str
    path: str
    domain: str
    lines: int
    classes: list[str]
    functions: list[str]
    internal_imports: list[str]
    external_imports: list[str]
    routes: list[str]
    execution_points: list[str]


class CodeRiskFinding(BaseModel):
    severity: Literal["low", "medium", "high"]
    rule: str
    module: str
    path: str
    line: int
    detail: str


class CodeArchitectureReport(BaseModel):
    contract: str = "zenthra.code_architecture.v1"
    scope: str
    analysis_mode: str = "static_ast_no_execution"
    component_count: int
    domain_count: int
    route_count: int
    execution_point_count: int
    internal_dependency_count: int
    external_dependencies: list[str]
    domains: dict[str, list[str]]
    dependency_graph: dict[str, list[str]]
    components: list[CodeComponent]
    risks: list[CodeRiskFinding]
    limitations: list[str] = Field(default_factory=list)

