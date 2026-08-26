from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from typing import Literal

from fastapi import APIRouter, Depends, FastAPI, Request
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse

from app.core.errors import register_error_handlers
from app.core.observability.metrics import http_metrics_middleware
from app.core.observability.metrics import router as metrics_router
from app.core.security import require_admin_or_monitor_token
from app.core.settings import settings
from app.db.session import get_db
from app.health.router import router as system_health_router
from app.middlewares.audit_middleware import AuditMiddleware
from app.middlewares.request_id import RequestIdMiddleware

ProcessProfile = Literal["redqueen", "ares", "ingestion"]
LOG = logging.getLogger("vaelqorix.process")


def _include_router_routes(app: FastAPI, router: APIRouter) -> None:
    app.router.routes.extend(router.routes)


def create_restricted_application(
    profile: ProcessProfile,
    *,
    routers: Sequence[APIRouter],
) -> FastAPI:
    profile_app = FastAPI(
        title=f"{settings.PROJECT_NAME} - {profile}",
        version="1.0.0",
        description=f"Restricted VAELQORIX {profile} process API",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    register_error_handlers(profile_app)
    profile_app.add_middleware(RequestIdMiddleware)
    profile_app.add_middleware(AuditMiddleware)
    profile_app.middleware("http")(http_metrics_middleware())

    @profile_app.middleware("http")
    async def log_process_requests(request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        LOG.info(
            "profile=%s %s %s -> %s (%.2fms)",
            profile,
            request.method,
            request.url.path,
            response.status_code,
            (time.time() - start) * 1000,
        )
        return response

    _include_router_routes(profile_app, system_health_router)
    _include_router_routes(profile_app, metrics_router)
    for profile_router in routers:
        _include_router_routes(profile_app, profile_router)

    @profile_app.get("/health")
    def health():
        return {"status": "ok", "profile": profile}

    @profile_app.get("/ready")
    def ready(db: Session = Depends(get_db)):
        try:
            db.execute(text("SELECT 1"))
            return {"status": "ready", "profile": profile}
        except Exception as exc:
            return JSONResponse(status_code=503, content={"error": str(exc), "profile": profile})

    @profile_app.get("/process/status")
    def process_status(_=Depends(require_admin_or_monitor_token)):
        return {
            "profile": profile,
            "scheduler_owner": False,
            "route_domains": [router.prefix for router in routers],
            "isolation": "restricted_process_surface",
        }

    return profile_app
