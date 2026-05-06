from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from logging.handlers import RotatingFileHandler

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse

from app.ares.router import router as ares_router
from app.core.errors import register_error_handlers
from app.core.observability.metrics import http_metrics_middleware
from app.core.observability.metrics import router as metrics_router
from app.core.security import get_current_user, get_password_hash
from app.core.settings import settings
from app.db.session import SessionLocal, engine
from app.health.router import router as system_health_router
from app.ingestion.router import router as ingestion_router
from app.middlewares.audit_middleware import AuditMiddleware
from app.middlewares.request_id import RequestIdMiddleware
from app.models.user import User
from app.redqueen.router import router as redqueen_router
from app.routers import auth, monitoring, monitoring_correlation, monitoring_health, threats, users
from app.services.correlation_engine import correlation_engine

os.environ["PYTHONIOENCODING"] = "utf-8"
os.makedirs("logs", exist_ok=True)

log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")
log_handler = RotatingFileHandler(
    "logs/app.log", maxBytes=1_000_000, backupCount=5, encoding="utf-8"
)
log_handler.setFormatter(log_formatter)

logger = logging.getLogger("zenthra")
logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
if not logger.handlers:
    logger.addHandler(log_handler)
logger.propagate = False

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="ZENTHRA.CORE_SECURITY API",
)
register_error_handlers(app)


def _parse_cors_origins(raw_origins: str) -> list[str]:
    try:
        parsed = json.loads(raw_origins)
        if isinstance(parsed, list):
            return [str(origin).strip().rstrip("/") for origin in parsed if str(origin).strip()]
    except json.JSONDecodeError:
        pass
    return [origin.strip().rstrip("/") for origin in raw_origins.split(",") if origin.strip()]


app.add_middleware(
    CORSMiddleware,
    allow_origins=_parse_cors_origins(settings.CORS_ORIGINS),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestIdMiddleware)
app.add_middleware(AuditMiddleware)

app.middleware("http")(http_metrics_middleware())


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration_ms = (time.time() - start) * 1000
    logger.info(
        "%s %s -> %s (%.2fms)",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


correlation_task: asyncio.Task | None = None
correlation_lock = asyncio.Lock()


async def correlation_worker():
    await asyncio.sleep(int(settings.ZENTHRA_CORRELATION_STARTUP_DELAY_SEC))
    interval = int(settings.ZENTHRA_CORRELATION_INTERVAL_SEC)
    logger.info("Correlation worker ON (interval=%ss)", interval)

    while True:
        try:
            if correlation_lock.locked():
                await asyncio.sleep(interval)
                continue

            async with correlation_lock:
                db: Session = SessionLocal()
                try:
                    result = correlation_engine.run_correlation(db)
                    logger.info("Correlation result: %s", result)
                finally:
                    db.close()

        except asyncio.CancelledError:
            logger.info("Correlation worker cancelled")
            break
        except Exception:
            logger.exception("Correlation worker error")

        await asyncio.sleep(interval)


@app.on_event("startup")
async def startup():
    logger.info("ZENTHRA iniciado")
    logger.info("ENV=%s DB=%s", settings.ENV, settings.SQLALCHEMY_DATABASE_URI)

    if settings.ZENTHRA_CORRELATION_ENABLED:
        global correlation_task
        correlation_task = asyncio.create_task(correlation_worker())
        logger.info("Correlation scheduler started")


@app.on_event("startup")
def create_default_admin_dev():
    if settings.ENV != "development":
        return

    db: Session = SessionLocal()
    try:
        try:
            if db.query(User).first():
                return

            bootstrap_email = getattr(settings, "BOOTSTRAP_ADMIN_EMAIL", "admin@zenthra.dev")
            bootstrap_password = getattr(settings, "BOOTSTRAP_ADMIN_PASSWORD", None)
            if not bootstrap_password:
                logger.warning(
                    "Admin DEV no creado: configura BOOTSTRAP_ADMIN_PASSWORD para bootstrap local"
                )
                return

            admin = User(
                full_name="ZENTHRA SuperAdmin",
                email=bootstrap_email,
                hashed_password=get_password_hash(bootstrap_password),
                role="admin",
                is_active=True,
            )
            db.add(admin)
            db.commit()
            logger.info("Admin DEV creado")
        except Exception:
            logger.exception("No se pudo inicializar admin dev en startup")
    finally:
        db.close()


@app.on_event("shutdown")
async def shutdown():
    global correlation_task
    if correlation_task:
        correlation_task.cancel()
        try:
            await correlation_task
        except asyncio.CancelledError:
            pass


app.include_router(auth.router)
app.include_router(users.router)
app.include_router(threats.router)
app.include_router(monitoring.router)
app.include_router(monitoring_health.router)
app.include_router(monitoring_correlation.router)
app.include_router(monitoring.hooks_router)
app.include_router(metrics_router)

app.include_router(system_health_router)
app.include_router(ingestion_router)
app.include_router(redqueen_router)
app.include_router(ares_router)


@app.get("/", include_in_schema=False)
def root():
    # Redirige a la documentación interactiva
    return RedirectResponse(url="/docs")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    # Evita 404 de favicon cuando se abre en navegador
    return Response(status_code=204)


@app.get("/health")
def health():
    env_alias = {
        "development": "dev",
        "production": "prod",
        "testing": "test",
    }
    return {
        "status": "ok",
        "message": "El servidor está corriendo",
        "env": env_alias.get(settings.ENV, settings.ENV),
    }


@app.get("/ready")
def ready():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception as exc:
        return JSONResponse(status_code=503, content={"error": str(exc)})


@app.get("/debug/config")
def debug_config(current_user=Depends(get_current_user)):
    return {
        "ENV": settings.ENV,
        "DB": settings.SQLALCHEMY_DATABASE_URI,
        "CORRELATION_ENABLED": settings.ZENTHRA_CORRELATION_ENABLED,
        "CORRELATION_INTERVAL_SEC": settings.ZENTHRA_CORRELATION_INTERVAL_SEC,
    }


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }

    for path in schema.get("paths", {}).values():
        for method in path.values():
            method["security"] = [{"BearerAuth": []}]

    app.openapi_schema = schema
    return schema


app.openapi = custom_openapi  # type: ignore[method-assign]
