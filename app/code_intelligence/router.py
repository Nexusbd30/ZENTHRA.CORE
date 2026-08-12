from __future__ import annotations

from fastapi import APIRouter, Depends

from app.code_intelligence.analyzer import build_code_architecture_report
from app.code_intelligence.contracts import CodeAnalysisRequest, CodeArchitectureReport
from app.core.security import require_admin_or_monitor_token

router = APIRouter(
    prefix="/api/v1/code-intelligence",
    tags=["code-intelligence"],
    dependencies=[Depends(require_admin_or_monitor_token)],
)


@router.get("/status")
def code_intelligence_status():
    return {
        "module": "code_intelligence",
        "contract": "vaelqorix.code_architecture.v1",
        "status": "ready",
        "mode": "static_ast_no_execution",
        "scope": ["app"],
        "capabilities": [
            "component_inventory",
            "internal_dependency_graph",
            "route_inventory",
            "execution_point_inventory",
            "static_execution_risk_detection",
        ],
    }


@router.post("/analyze", response_model=CodeArchitectureReport)
def analyze_backend_code(payload: CodeAnalysisRequest):
    return build_code_architecture_report(include_private=payload.include_private)

