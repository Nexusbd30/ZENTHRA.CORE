from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import APIRouter
from httpx import ASGITransport, AsyncClient

from app.code_intelligence import analyzer
from app.code_intelligence.contracts import CodeAnalysisRequest
from app.code_intelligence.router import analyze_backend_code, code_intelligence_status
from app.core.security import require_admin_or_monitor_token
from app.db.session import get_db
from app.process_factory import create_restricted_application

FIXTURE_BACKEND = Path("fixtures/code_intelligence/app").resolve()


def test_code_intelligence_builds_static_architecture_report(monkeypatch):
    monkeypatch.setattr(analyzer, "BACKEND_ROOT", FIXTURE_BACKEND)

    report = analyzer.build_code_architecture_report(include_private=False)

    assert report.analysis_mode == "static_ast_no_execution"
    assert report.component_count == 4
    assert report.domain_count == 2
    assert report.route_count == 2
    assert report.execution_point_count == 1
    assert report.dependency_graph["app.domain.service"] == ["app.domain.worker"]
    assert report.external_dependencies == ["fastapi"]
    assert {finding.rule for finding in report.risks} == {"shell_execution", "syntax_error"}

    service = next(item for item in report.components if item.module == "app.domain.service")
    assert service.classes == ["PublicService"]
    assert service.functions == ["public_function"]
    assert service.internal_imports == ["app.domain.worker"]

    worker = next(item for item in report.components if item.module == "app.domain.worker")
    assert worker.routes == ["GET /items", "POST <dynamic>"]
    assert worker.execution_points == ["function:startup"]


def test_code_intelligence_private_inventory_and_router_contract(monkeypatch):
    monkeypatch.setattr(analyzer, "BACKEND_ROOT", FIXTURE_BACKEND)

    report = analyze_backend_code(CodeAnalysisRequest(include_private=True))
    status = code_intelligence_status()

    service = next(item for item in report.components if item.module == "app.domain.service")
    assert "_PrivateService" in service.classes
    assert "_private_function" in service.functions
    assert status["mode"] == "static_ast_no_execution"
    assert "component_inventory" in status["capabilities"]


class _ReadyDb:
    def execute(self, statement):
        return statement


class _BrokenDb:
    def execute(self, statement):
        raise RuntimeError("database unavailable")


def _db_override(database):
    def override():
        yield database

    return override


@pytest.mark.asyncio
async def test_restricted_process_surface_and_readiness():
    owned_router = APIRouter(prefix="/owned")

    @owned_router.get("/status")
    def owned_status():
        return {"owned": True}

    app = create_restricted_application("ares", routers=[owned_router])
    app.dependency_overrides[get_db] = _db_override(_ReadyDb())
    app.dependency_overrides[require_admin_or_monitor_token] = lambda: {"role": "internal"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        health = await client.get("/health")
        ready = await client.get("/ready")
        process = await client.get("/process/status")
        owned = await client.get("/owned/status")
        docs = await client.get("/docs")

    assert health.json() == {"status": "ok", "profile": "ares"}
    assert ready.json() == {"status": "ready", "profile": "ares"}
    assert process.json()["scheduler_owner"] is False
    assert process.json()["route_domains"] == ["/owned"]
    assert owned.json() == {"owned": True}
    assert docs.status_code == 404
    assert app.router.on_startup == []


@pytest.mark.asyncio
async def test_restricted_process_readiness_fails_closed():
    app = create_restricted_application("ingestion", routers=[])
    app.dependency_overrides[get_db] = _db_override(_BrokenDb())

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/ready")

    assert response.status_code == 503
    assert response.json() == {"error": "database unavailable", "profile": "ingestion"}


def test_restricted_entrypoints_do_not_expose_cross_domain_routes():
    from app.entrypoints.ares import app as ares_app
    from app.entrypoints.ingestion import app as ingestion_app
    from app.entrypoints.redqueen import app as redqueen_app

    ares_paths = {route.path for route in ares_app.routes}
    ingestion_paths = {route.path for route in ingestion_app.routes}
    redqueen_paths = {route.path for route in redqueen_app.routes}

    assert any(path.startswith("/api/v1/ares") for path in ares_paths)
    assert not any(path.startswith("/api/v1/redqueen") for path in ares_paths)
    assert any(path.startswith("/api/v1/ingest") for path in ingestion_paths)
    assert not any(path.startswith("/api/v1/ares") for path in ingestion_paths)
    assert any(path.startswith("/api/v1/redqueen") for path in redqueen_paths)
    assert not any(path.startswith("/api/v1/ingest") for path in redqueen_paths)
