from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

from app.core.internal_auth import require_internal_bearer

HTTP_REQS = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)
HTTP_LAT = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "path"],
)


def http_metrics_middleware():
    async def middleware(request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        duration = time.time() - start
        path_template = request.url.path[:64]
        HTTP_LAT.labels(request.method, path_template).observe(duration)
        HTTP_REQS.labels(request.method, path_template, str(response.status_code)).inc()
        return response

    return middleware


THREATS_CREATED = Counter(
    "zenthra_threats_created_total",
    "Threats created",
    ["source", "level"],
)
THREATS_DELETED = Counter("zenthra_threats_deleted_total", "Threats deleted")
SCANNER_RUNNING = Gauge("zenthra_scanner_running", "Scanner running flag")
SECURITY_WEBHOOK_REJECTIONS = Counter(
    "zenthra_security_webhook_rejections_total",
    "Security webhook rejections",
    ["provider", "reason", "status_code"],
)
SECURITY_RATE_LIMIT_REJECTIONS = Counter(
    "zenthra_security_rate_limit_rejections_total",
    "Security webhook rate limit rejections",
    ["provider"],
)
SECURITY_REPLAY_REJECTIONS = Counter(
    "zenthra_security_replay_rejections_total",
    "Security webhook replay rejections",
    ["provider"],
)
SOC_MATERIALIZATIONS = Counter(
    "zenthra_soc_materializations_total",
    "SOC security events materialized as threat events",
    ["event_type", "status"],
)
SOC_LIFECYCLES = Counter(
    "zenthra_soc_lifecycles_total",
    "SOC security event lifecycles routed through RedQueen and ARES",
    ["event_type", "status"],
)


def record_security_webhook_rejection(*, provider: str, reason: str, status_code: int) -> None:
    SECURITY_WEBHOOK_REJECTIONS.labels(provider, reason, str(status_code)).inc()
    if reason == "rate_limit_exceeded":
        SECURITY_RATE_LIMIT_REJECTIONS.labels(provider).inc()
    if reason == "replay_detected":
        SECURITY_REPLAY_REJECTIONS.labels(provider).inc()


def record_soc_materialization(*, event_type: str, status: str) -> None:
    SOC_MATERIALIZATIONS.labels(event_type, status).inc()


def record_soc_lifecycle(*, event_type: str, status: str) -> None:
    SOC_LIFECYCLES.labels(event_type, status).inc()

router = APIRouter()


@router.get("/metrics")
def metrics_endpoint(_: None = Depends(require_internal_bearer)):
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)
