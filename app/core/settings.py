# =============================================================
# 💠 ZENTHRA — SETTINGS dinámicos (Pydantic v2) · v3.9 Postgres-Ready SAFE
# =============================================================
# - Lee .env en la raíz del repo backend
# - Ignora variables extra (extra="ignore")
#
# ✅ Mejora clave:
#   - Si construye Postgres URI con POSTGRES_*, ESCAPA user/password con quote_plus
#     (evita UnicodeDecodeError y problemas con caracteres especiales)
#
# Mantiene compatibilidad:
#   PROMETHEUS_BASE_URL / ALERTMANAGER_BASE_URL
# =============================================================

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import quote_plus, urlparse, urlunparse

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # ---------------------------------------------------------
    # Identidad / ejecución
    # ---------------------------------------------------------
    PROJECT_NAME: str = "ZENTHRA.CORE_SECURITY"
    ENV: str = "development"
    LOG_LEVEL: str = "INFO"

    # ---------------------------------------------------------
    # Seguridad
    # ---------------------------------------------------------
    SECRET_KEY: str = "change-me"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    BOOTSTRAP_ADMIN_EMAIL: str = "admin@zenthra.dev"
    BOOTSTRAP_ADMIN_PASSWORD: str | None = None
    ENTERPRISE_TENANT_MODE: str = "single_tenant"  # single_tenant | header_scoped | strict
    DEFAULT_TENANT_ID: str = "default"
    ENTERPRISE_RBAC_ENABLED: bool = True

    # ---------------------------------------------------------
    # Base de datos
    # ---------------------------------------------------------
    # Opción A (simple): define SQLALCHEMY_DATABASE_URI en .env
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///./app.db"

    # Opción B (pro): define POSTGRES_* y se construye el URI
    POSTGRES_HOST: str | None = None
    POSTGRES_PORT: int = 5432
    ZENTHRA_POSTGRES_PORT: int | None = None
    POSTGRES_DB: str | None = None
    POSTGRES_USER: str | None = None
    POSTGRES_PASSWORD: str | None = None

    # ---------------------------------------------------------
    # CORS
    # ---------------------------------------------------------
    CORS_ORIGINS: str = (
        '["http://localhost:5173","http://127.0.0.1:5173",'
        '"http://localhost:3000","http://127.0.0.1:3000"]'
    )

    # ---------------------------------------------------------
    # Observabilidad
    # ---------------------------------------------------------
    PROMETHEUS_BASE: str = "http://localhost:9090"
    ALERTMANAGER_BASE: str = "http://localhost:9093"
    ALERTMANAGER_ALLOWED_CIDRS: str = "172.20.0.0/16,127.0.0.1/32,::1/128"
    PROM_TIMEOUT_SEC: float = 8.0

    # Aliases legacy
    PROMETHEUS_BASE_URL: str | None = None
    ALERTMANAGER_BASE_URL: str | None = None

    # ---------------------------------------------------------
    # Token interno (para /metrics y /monitoring/*)
    # ---------------------------------------------------------
    ZENTHRA_MONITOR_TOKEN: str | None = None

    # ---------------------------------------------------------
    # 🧠 Correlation Engine — Scheduler (PROD)
    # ---------------------------------------------------------
    ZENTHRA_CORRELATION_ENABLED: bool = True
    ZENTHRA_CORRELATION_INTERVAL_SEC: int = 60
    ZENTHRA_CORRELATION_STARTUP_DELAY_SEC: int = 5
    ZENTHRA_ENABLE_LAB_ALERTS: bool = False

    # ---------------------------------------------------------
    # AI / LLM control plane (RedQueen)
    # ---------------------------------------------------------
    AI_ENABLED: bool = True
    AI_PROVIDER: str = "local_stub"  # local_stub | ollama
    AI_MODEL: str = "llama3.1:8b"
    AI_BASE_URL: str = "http://127.0.0.1:11434"
    AI_TIMEOUT_SEC: float = 8.0
    AI_TEMPERATURE: float = 0.1

    # MCP / operational context bridge
    MCP_CONTEXT_ENABLED: bool = True
    MCP_CONTEXT_MODE: str = "manual_context"  # manual_context | external_mcp

    # Vector memory / semantic context
    VECTOR_STORE_ENABLED: bool = True
    VECTOR_STORE_PROVIDER: str = "local"  # local | qdrant | milvus
    VECTOR_DIMENSIONS: int = 64
    VECTOR_COLLECTION_PREFIX: str = "zenthra"

    # Streaming ingestion
    KAFKA_INGESTION_ENABLED: bool = False
    KAFKA_BOOTSTRAP_SERVERS: str = "127.0.0.1:9092"
    KAFKA_INGESTION_TOPICS: str = "zenthra.siem,zenthra.edr,zenthra.iam,zenthra.netflow"
    KAFKA_CONSUMER_GROUP_ID: str = "zenthra-core-ingestion"
    KAFKA_AUTO_OFFSET_RESET: str = "latest"
    KAFKA_POLL_TIMEOUT_SEC: float = 1.0

    # Governance thresholds
    REDQUEEN_AUTONOMY_MAX: float = 80.0
    REDQUEEN_HUMAN_APPROVAL_SCORE: float = 80.0

    # ---------------------------------------------------------
    # ARES execution adapters
    # ---------------------------------------------------------
    ACTION_EXECUTION_MODE: str = "mock"  # mock | dry_run | webhook
    ACTION_TIMEOUT_SEC: float = 5.0
    ACTION_SHARED_TOKEN: str | None = None

    NETWORK_CONTROL_URL: str | None = None
    IDENTITY_CONTROL_URL: str | None = None
    ENTRA_GRAPH_ENABLED: bool = False
    ENTRA_GRAPH_BASE_URL: str = "https://graph.microsoft.com/v1.0"
    ENTRA_GRAPH_TOKEN_URL: str | None = None
    ENTRA_GRAPH_SCOPE: str = "https://graph.microsoft.com/.default"
    ENTRA_TENANT_ID: str | None = None
    ENTRA_CLIENT_ID: str | None = None
    ENTRA_CLIENT_SECRET: str | None = None
    ENTRA_REQUIRE_MFA_POLICY_URL: str | None = None
    ENTRA_DEGRADE_PRIVILEGES_GROUP_IDS: str = ""
    ENTRA_WEBHOOK_SECRET: str | None = None
    ENTRA_WEBHOOK_MAX_SKEW_SEC: int = 300
    ENTRA_WEBHOOK_RATE_LIMIT_ENABLED: bool = True
    ENTRA_WEBHOOK_RATE_LIMIT_REQUESTS: int = 120
    ENTRA_WEBHOOK_RATE_LIMIT_WINDOW_SEC: int = 60
    ENTRA_WEBHOOK_REPLAY_GUARD_ENABLED: bool = True
    ENTRA_WEBHOOK_REPLAY_TTL_SEC: int = 300
    ENDPOINT_CONTROL_URL: str | None = None
    SOAR_CONTROL_URL: str | None = None
    CRYPTO_CONTROL_URL: str | None = None
    DEVSECOPS_CONTROL_URL: str | None = None

    # ---------------------------------------------------------
    # Pydantic settings config
    # ---------------------------------------------------------
    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).resolve().parents[2] / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    @model_validator(mode="after")
    def validate_security_defaults(self):
        env = str(self.ENV or "").lower()
        weak_secret = not self.SECRET_KEY or self.SECRET_KEY.lower() in {
            "change-me",
            "changeme",
            "secret",
            "dev-secret",
        }
        if env in {"production", "prod"}:
            if weak_secret:
                raise ValueError("SECRET_KEY seguro requerido en produccion")
            if not self.ZENTHRA_MONITOR_TOKEN:
                raise ValueError("ZENTHRA_MONITOR_TOKEN requerido en produccion")
        return self


settings = Settings()


def _prefer_ipv4_loopback(url: str | None) -> str | None:
    if not url:
        return url
    parsed = urlparse(url)
    if parsed.hostname != "localhost":
        return url
    netloc = "127.0.0.1"
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunparse(parsed._replace(netloc=netloc))


settings.PROMETHEUS_BASE = _prefer_ipv4_loopback(settings.PROMETHEUS_BASE) or settings.PROMETHEUS_BASE
settings.ALERTMANAGER_BASE = (
    _prefer_ipv4_loopback(settings.ALERTMANAGER_BASE) or settings.ALERTMANAGER_BASE
)

# -------------------------------------------------------------
# 🧠 Post-procesado: construir URI Postgres si POSTGRES_* existe
# -------------------------------------------------------------
# ✅ CLAVE: escapamos user/password para evitar UnicodeDecodeError y caracteres especiales
postgres_config_complete = all(
    [
        settings.POSTGRES_HOST,
        settings.POSTGRES_DB,
        settings.POSTGRES_USER,
        settings.POSTGRES_PASSWORD,
    ]
)
explicit_database_uri = bool(os.environ.get("SQLALCHEMY_DATABASE_URI"))
explicit_postgres_config = all(
    os.environ.get(key)
    for key in ("POSTGRES_HOST", "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD")
)

if postgres_config_complete and (not explicit_database_uri or explicit_postgres_config):
    pg_user = quote_plus(str(settings.POSTGRES_USER))
    pg_pass = quote_plus(str(settings.POSTGRES_PASSWORD))
    pg_port = (
        int(settings.POSTGRES_PORT)
        if explicit_postgres_config or settings.ZENTHRA_POSTGRES_PORT is None
        else int(settings.ZENTHRA_POSTGRES_PORT)
    )

    settings.SQLALCHEMY_DATABASE_URI = (
        "postgresql+psycopg://"
        f"{pg_user}:{pg_pass}"
        f"@{settings.POSTGRES_HOST}:{pg_port}"
        f"/{settings.POSTGRES_DB}"
    )

# Aliases legacy
if settings.PROMETHEUS_BASE_URL is None:
    settings.PROMETHEUS_BASE_URL = settings.PROMETHEUS_BASE
else:
    settings.PROMETHEUS_BASE_URL = _prefer_ipv4_loopback(settings.PROMETHEUS_BASE_URL)

if settings.ALERTMANAGER_BASE_URL is None:
    settings.ALERTMANAGER_BASE_URL = settings.ALERTMANAGER_BASE
else:
    settings.ALERTMANAGER_BASE_URL = _prefer_ipv4_loopback(settings.ALERTMANAGER_BASE_URL)

# Hardening suave
if settings.ZENTHRA_CORRELATION_INTERVAL_SEC < 5:
    settings.ZENTHRA_CORRELATION_INTERVAL_SEC = 5

if settings.ZENTHRA_CORRELATION_STARTUP_DELAY_SEC < 0:
    settings.ZENTHRA_CORRELATION_STARTUP_DELAY_SEC = 0
