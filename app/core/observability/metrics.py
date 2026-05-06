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

router = APIRouter()


@router.get("/metrics")
def metrics_endpoint(_: None = Depends(require_internal_bearer)):
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)
