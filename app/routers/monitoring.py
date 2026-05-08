# =============================================================
# 🛰️ MONITORING — ZENTHRA.CORE v4.2 (Elite-Hardening)
# =============================================================
# Responsabilidades:
#   - /monitoring/* protegido por Bearer interno (ZENTHRA_MONITOR_TOKEN)
#   - /hooks/alertmanager protegido por IP Whitelist (red Docker)
#   - Config dinámica via app.core.settings (lee .env)
#
# Notas:
#   - El frontend usa VITE_ZENTHRA_MONITOR_TOKEN para llamar aquí.
#   - Ningún JWT de usuario da acceso a /monitoring/*.
#   - El webhook de Alertmanager SOLO acepta tráfico de la red Docker.
# =============================================================

import hashlib
import json
import logging
import time
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Any, Optional

import httpx
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
)
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.security import require_admin_or_monitor_token
from app.core.settings import settings  # ✅ Config dinámica desde .env
from app.db.session import get_db  # 🔁 Ajusta este import si tu get_db está en otro módulo
from app.models.response_log import ResponseLog
from app.schemas.monitoring_schema import (
    AlertmanagerHookResponse,
    ProductionReadinessResponse,
    ResponseLogRead,
    RuntimeLogsResponse,
)
from app.services.runtime_log_service import list_runtime_logs

_require_internal_bearer = require_admin_or_monitor_token


# =============================================================
# 🛡️ Whitelist por IP para /hooks/alertmanager
# =============================================================


def _alertmanager_allowed_cidrs() -> list[str]:
    raw = getattr(settings, "ALERTMANAGER_ALLOWED_CIDRS", "")
    return [cidr.strip() for cidr in str(raw).split(",") if cidr.strip()]


def _alertmanager_allowed_nets():
    return [ip_network(cidr) for cidr in _alertmanager_allowed_cidrs()]


def _require_docker_network_source(request: Request) -> None:
    """
    Solo permite llamadas al webhook desde IPs dentro de las
    redes definidas en ALERTMANAGER_ALLOWED_CIDRS.
    """
    client = request.client
    client_ip = client.host if client else None
    if not client_ip:
        raise HTTPException(status_code=400, detail="No se pudo determinar IP de origen")
    try:
        ip_obj = ip_address(client_ip)
    except ValueError as err:
        raise HTTPException(status_code=400, detail="IP de origen inválida") from err

    try:
        allowed_nets = _alertmanager_allowed_nets()
    except ValueError as err:
        raise HTTPException(
            status_code=500,
            detail="ALERTMANAGER_ALLOWED_CIDRS contiene una red inválida",
        ) from err

    if not any(ip_obj in net for net in allowed_nets):
        raise HTTPException(
            status_code=403,
            detail="IP no permitida para webhook",
        )


# =============================================================
# ⚙️ Config dinámica (Prometheus / Alertmanager / timeout)
# =============================================================

PROMETHEUS_BASE = settings.PROMETHEUS_BASE
PROM_API = f"{PROMETHEUS_BASE}/api/v1"
PROMETHEUS_ALERTS = f"{PROM_API}/alerts"
PROMETHEUS_HEALTH = f"{PROMETHEUS_BASE}/-/healthy"

ALERTMANAGER_BASE = settings.ALERTMANAGER_BASE
ALERTMANAGER_ALERTS = f"{ALERTMANAGER_BASE}/api/v2/alerts"

HTTP_TIMEOUT = float(
    getattr(
        settings,
        "PROM_TIMEOUT_SECONDS",
        getattr(settings, "PROM_TIMEOUT_SEC", 8.0),
    )
)
PROM_CACHE_TTL_SECONDS = float(getattr(settings, "PROM_CACHE_TTL_SECONDS", 5.0))
_PROM_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}

# Logger de auditoría (configurado en main.py)
AUDIT_LOG = logging.getLogger("alerts_audit")

UI_ROLE_CAPABILITIES = {
    "admin": [
        "users.manage",
        "threats.write",
        "monitoring.read",
        "redqueen.control",
        "ares.execute",
        "audit.read",
    ],
    "analyst": [
        "threats.read",
        "monitoring.read",
        "redqueen.read",
        "ares.plan",
        "audit.read",
    ],
    "operator": [
        "threats.read",
        "monitoring.read",
        "ares.plan",
        "ares.execute_dry_run",
    ],
    "viewer": [
        "threats.read",
        "monitoring.read",
        "audit.read",
    ],
}


def _production_readiness_report() -> dict[str, Any]:
    ai_provider = str(getattr(settings, "AI_PROVIDER", "local_stub") or "local_stub").lower()
    action_mode = str(getattr(settings, "ACTION_EXECUTION_MODE", "mock") or "mock").lower()
    warnings = []

    if ai_provider in {"local_stub", "stub", "mock"}:
        warnings.append("AI_PROVIDER usa modo laboratorio; configurar ollama/openai/azure_openai.")
    if action_mode in {"mock", "dry_run"}:
        warnings.append("ACTION_EXECUTION_MODE no ejecuta acciones reales; configurar webhook.")
    if action_mode == "webhook" and not getattr(settings, "ACTION_SHARED_TOKEN", None):
        warnings.append("ACTION_SHARED_TOKEN requerido para ejecucion webhook real.")
    if not _alertmanager_allowed_cidrs():
        warnings.append("ALERTMANAGER_ALLOWED_CIDRS esta vacio.")

    return {
        "environment": settings.ENV,
        "status": "ready" if not warnings else "needs_attention",
        "ai": {
            "enabled": bool(settings.AI_ENABLED),
            "provider": ai_provider,
            "model": settings.AI_MODEL,
            "real_mode": ai_provider not in {"local_stub", "stub", "mock"},
        },
        "ares": {
            "execution_mode": action_mode,
            "real_mode": action_mode == "webhook",
            "shared_token_configured": bool(getattr(settings, "ACTION_SHARED_TOKEN", None)),
            "control_urls_configured": {
                "network": bool(settings.NETWORK_CONTROL_URL),
                "identity": bool(settings.IDENTITY_CONTROL_URL),
                "endpoint": bool(settings.ENDPOINT_CONTROL_URL),
                "soar": bool(settings.SOAR_CONTROL_URL),
                "crypto": bool(settings.CRYPTO_CONTROL_URL),
            },
        },
        "monitoring": {
            "response_logs_persistent": True,
            "alertmanager_allowed_cidrs": _alertmanager_allowed_cidrs(),
        },
        "frontend_contracts": {
            "response_logs": "/monitoring/response-logs",
            "runtime_logs": "/monitoring/logs",
            "redqueen_verdict": "/api/v1/redqueen/verdict",
            "ares_lifecycle": "/api/v1/ares/lifecycle",
            "ares_execution_results": "/api/v1/ares/results/{verdict_id}",
        },
        "ui_rbac": UI_ROLE_CAPABILITIES,
        "warnings": warnings,
    }

# =============================================================
# 🔗 Routers
# =============================================================

router = APIRouter(
    prefix="/monitoring",
    tags=["Monitoring"],
    dependencies=[Depends(_require_internal_bearer)],
)

# Webhook sin prefijo, pero con protección por IP
hooks_router = APIRouter(tags=["Alertmanager Hooks"])

# =============================================================
# 🔎 Debug seguro
# =============================================================


@router.get("/alerts/_debug")
def debug_alerts_base():
    """
    Endpoint de diagnóstico rápido (solo accesible con monitor token).
    No expone secretos, solo la configuración efectiva de endpoints.
    """
    return {
        "ALERTMANAGER_BASE": ALERTMANAGER_BASE,
        "PROMETHEUS_BASE": PROMETHEUS_BASE,
        "HTTP_TIMEOUT": HTTP_TIMEOUT,
        "ALERTMANAGER_ALLOWED_CIDRS": _alertmanager_allowed_cidrs(),
    }


@router.get("/production-readiness", response_model=ProductionReadinessResponse)
def get_production_readiness():
    """
    Contrato operativo para UI/CI: modos reales, RBAC visual y gaps activos.
    """
    return _production_readiness_report()


# =============================================================
# 🔔 Prometheus: Alerts / Health
# =============================================================


@router.get("/alerts")
async def get_alerts():
    """
    Devuelve la estructura JSON nativa de /api/v1/alerts de Prometheus.
    Usado normalmente solo a nivel interno (Debug / SOC avanzado).
    """
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            r = await client.get(PROMETHEUS_ALERTS)
            r.raise_for_status()
        return r.json()
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=502,
            detail=f"No se pudo conectar a Prometheus: {e}",
        ) from e
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=502,
            detail=(
                f"Prometheus devolvió {e.response.status_code}: "
                f"{e.response.text[:200]}"
            ),
        ) from e


@router.get("/health")
async def monitoring_health():
    """
    Healthcheck de Prometheus visto desde ZENTHRA.
    """
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            r = await client.get(PROMETHEUS_HEALTH)
            r.raise_for_status()
        return {"status": "ok", "prometheus": "healthy"}
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Prometheus no responde (red/timeout): {e}",
        ) from e
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=502,
            detail=(
                f"Prometheus no está healthy "
                f"({e.response.status_code})"
            ),
        ) from e


# =============================================================
# 📈 PromQL — query y range
# =============================================================


@router.get("/query")
async def prom_query(q: str = Query(..., alias="q")):
    """
    Proxy seguro a /api/v1/query de Prometheus.
    El frontend manda 'q' y aquí se reenvía como 'query'.
    """
    try:
        return await _cached_prometheus_get("/query", {"query": q})
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Error de red en /query: {e}",
        ) from e
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=502,
            detail=(
                f"Prometheus /query {e.response.status_code}: "
                f"{e.response.text[:200]}"
            ),
        ) from e


@router.get("/range")
async def prom_range(
    q: str = Query(..., alias="q"),
    start: float | None = None,
    end: float | None = None,
    step: str = "15s",
):
    """
    Proxy seguro a /api/v1/query_range de Prometheus.

    - Si no se especifica start/end, devuelve los últimos 10 minutos.
    - 'step' controla la resolución temporal (por defecto 15s).
    """
    try:
        now = datetime.utcnow().timestamp()
        start_ts = start or (now - 10 * 60)
        end_ts = end or now

        return await _cached_prometheus_get(
            "/query_range",
            {"query": q, "start": start_ts, "end": end_ts, "step": step},
        )
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Error de red en /range: {e}",
        ) from e
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=502,
            detail=(
                f"Prometheus /query_range {e.response.status_code}: "
                f"{e.response.text[:200]}"
            ),
        ) from e


async def _prometheus_query_result(query: str) -> list[dict]:
    payload = await _cached_prometheus_get("/query", {"query": query})
    return payload.get("data", {}).get("result", []) or []


@router.get("/windows/nics")
async def list_windows_nics():
    """
    Devuelve las NICs detectadas por Prometheus desde windows_exporter.
    No inventa adaptadores: si Prometheus no scrapea windows_exporter, devuelve [].
    """
    queries = [
        "sum by (nic, instance, job) (windows_net_bytes_total)",
        "sum by (nic, instance, job) (windows_net_bytes_received_total)",
        "sum by (nic, instance, job) (windows_net_bytes_sent_total)",
    ]

    try:
        results: list[dict] = []
        for query in queries:
            results = await _prometheus_query_result(query)
            if results:
                break
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Error de red obteniendo NICs: {e}") from e
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Prometheus NIC query {e.response.status_code}: {e.response.text[:200]}",
        ) from e

    seen: set[tuple[str, str]] = set()
    items: list[dict] = []
    for row in results:
        metric = row.get("metric", {}) or {}
        name = str(metric.get("nic") or metric.get("device") or "").strip()
        instance = str(metric.get("instance") or "").strip()
        if not name:
            continue
        key = (name, instance)
        if key in seen:
            continue
        seen.add(key)
        items.append(
            {
                "name": name,
                "instance": instance,
                "job": metric.get("job", "windows-exporter"),
            }
        )

    return {"data": items, "count": len(items)}


@router.get("/gpu/summary")
async def gpu_summary():
    """
    Devuelve una instantánea de GPU si hay exporter disponible.
    Soporta métricas comunes de DCGM, nvidia-smi exporter y windows_exporter.
    """
    candidates = [
        {
            "query": "avg(DCGM_FI_DEV_GPU_UTIL)",
            "source": "dcgm-exporter",
            "unit": "percent",
        },
        {
            "query": "avg(nvidia_smi_utilization_gpu_ratio) * 100",
            "source": "nvidia-smi-exporter",
            "unit": "percent",
        },
        {
            "query": "avg(nvidia_smi_utilization_gpu)",
            "source": "nvidia-smi-exporter",
            "unit": "percent",
        },
        {
            "query": "avg(windows_gpu_engine_utilization_percentage)",
            "source": "windows-exporter",
            "unit": "percent",
        },
    ]

    errors: list[str] = []
    for candidate in candidates:
        try:
            results = await _prometheus_query_result(candidate["query"])
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"Error de red obteniendo GPU: {e}") from e
        except httpx.HTTPStatusError as e:
            errors.append(f"{candidate['source']}: {e.response.status_code}")
            continue

        if not results:
            continue

        raw = results[0].get("value", [None, None])[1]
        try:
            value = float(raw)
        except (TypeError, ValueError):
            continue

        return {
            "available": True,
            "utilization_percent": max(0.0, min(value, 100.0)),
            "source": candidate["source"],
            "query": candidate["query"],
            "unit": candidate["unit"],
        }

    return {
        "available": False,
        "utilization_percent": None,
        "source": None,
        "query": None,
        "unit": "percent",
        "errors": errors,
    }


@router.get("/host/summary")
async def host_summary():
    """
    Instantánea agregada del host en una sola llamada para evitar abanicos de
    peticiones desde el frontend. No inventa valores: cada métrica indica si
    está disponible y qué consulta la originó.
    """
    cpu = await _first_prometheus_scalar(
        ['100 - (avg(rate(windows_cpu_time_total{mode="idle"}[2m])) * 100)']
    )
    memory = await _first_prometheus_scalar(
        [
            "100 * (1 - (windows_os_physical_memory_free_bytes / windows_cs_physical_memory_bytes))",
            "100 * (1 - (windows_memory_available_bytes / windows_cs_physical_memory_bytes))",
        ]
    )
    latency = await _first_prometheus_scalar(
        ['avg(probe_duration_seconds{job="blackbox_http"}) * 1000']
    )

    nics_payload = await list_windows_nics()
    nics = nics_payload.get("data", []) if isinstance(nics_payload, dict) else []
    primary_nic = None
    for nic in nics:
        name = str(nic.get("name") or "")
        if name and ("ethernet" in name.lower() or "lan" in name.lower() or "wi-fi" in name.lower()):
            primary_nic = name
            break
    if not primary_nic and nics:
        primary_nic = str(nics[0].get("name") or "") or None

    network = {"available": False, "value": None, "query": None, "nic": primary_nic}
    if primary_nic:
        nic_escaped = primary_nic.replace("\\", "\\\\").replace('"', '\\"')
        network = await _first_prometheus_scalar(
            [
                f'sum(rate(windows_net_bytes_total{{nic="{nic_escaped}"}}[2m])) * 8 / 1024 / 1024',
                (
                    f'(sum(rate(windows_net_bytes_received_total{{nic="{nic_escaped}"}}[2m])) + '
                    f'sum(rate(windows_net_bytes_sent_total{{nic="{nic_escaped}"}}[2m]))) * 8 / 1024 / 1024'
                ),
            ]
        )
        network["nic"] = primary_nic

    gpu = await gpu_summary()

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "cache_ttl_seconds": PROM_CACHE_TTL_SECONDS,
        "cpu_percent": cpu,
        "memory_percent": memory,
        "network_mbps": network,
        "latency_ms": latency,
        "gpu": gpu,
        "nics": nics,
    }


@router.get("/sources/diagnostics")
async def source_diagnostics(db: Session = Depends(get_db)):
    """
    Diagnóstico operativo de fuentes reales: backend, DB, Prometheus,
    Alertmanager, windows_exporter, GPU y logs locales.
    """
    sources: dict[str, dict[str, Any]] = {
        "backend": {"status": "up", "detail": "FastAPI handler responding"},
        "database": {"status": "unknown", "detail": None},
        "prometheus": {"status": "unknown", "detail": PROMETHEUS_BASE},
        "alertmanager": {"status": "unknown", "detail": ALERTMANAGER_BASE},
        "windows_exporter": {"status": "unknown", "detail": None},
        "gpu": {"status": "unknown", "detail": None},
        "logs": {"status": "unknown", "detail": None},
    }

    try:
        db.execute(text("SELECT 1"))
        sources["database"] = {"status": "up", "detail": "SELECT 1 ok"}
    except Exception as e:  # noqa: BLE001
        sources["database"] = {"status": "down", "detail": str(e)}

    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(f"{PROMETHEUS_BASE}/-/ready")
        sources["prometheus"]["status"] = "up" if response.status_code == 200 else "down"
        sources["prometheus"]["http_status"] = response.status_code
    except Exception as e:  # noqa: BLE001
        sources["prometheus"] = {"status": "down", "detail": str(e)}

    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(f"{ALERTMANAGER_BASE}/-/ready")
        sources["alertmanager"]["status"] = "up" if response.status_code == 200 else "down"
        sources["alertmanager"]["http_status"] = response.status_code
    except Exception as e:  # noqa: BLE001
        sources["alertmanager"] = {"status": "down", "detail": str(e)}

    try:
        nics_payload = await list_windows_nics()
        count = int(nics_payload.get("count", 0))
        sources["windows_exporter"] = {
            "status": "up" if count > 0 else "missing",
            "detail": f"{count} NIC(s) detected",
        }
    except HTTPException as e:
        sources["windows_exporter"] = {"status": "down", "detail": str(e.detail)}

    try:
        gpu_payload = await gpu_summary()
        sources["gpu"] = {
            "status": "up" if gpu_payload.get("available") else "missing",
            "detail": gpu_payload.get("source") or "GPU exporter no detectado",
        }
    except HTTPException as e:
        sources["gpu"] = {"status": "down", "detail": str(e.detail)}

    try:
        logs_payload = list_runtime_logs(limit=1)
        sources["logs"] = {
            "status": "up" if logs_payload.get("files") else "missing",
            "detail": ", ".join(logs_payload.get("files", [])) or "sin ficheros de logs",
        }
    except Exception as e:  # noqa: BLE001
        sources["logs"] = {"status": "down", "detail": str(e)}

    overall = "up"
    if any(item["status"] == "down" for item in sources.values()):
        overall = "degraded"
    if sources["backend"]["status"] != "up" or sources["database"]["status"] == "down":
        overall = "down" if sources["database"]["status"] == "down" else overall

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "overall": overall,
        "sources": sources,
    }


def _cache_key(path: str, params: dict[str, Any] | None = None) -> str:
    safe_params = params or {}
    return json.dumps(
        {"path": path, "params": sorted((str(k), str(v)) for k, v in safe_params.items())},
        separators=(",", ":"),
        sort_keys=True,
    )


async def _cached_prometheus_get(path: str, params: dict[str, Any] | None = None) -> dict:
    key = _cache_key(path, params)
    now = time.monotonic()
    cached = _PROM_CACHE.get(key)
    if cached and now - cached[0] <= PROM_CACHE_TTL_SECONDS:
        return cached[1]

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        response = await client.get(f"{PROM_API}{path}", params=params)
        response.raise_for_status()
    payload = response.json()
    _PROM_CACHE[key] = (now, payload)
    return payload


def _first_scalar(results: list[dict]) -> float | None:
    if not results:
        return None
    raw = results[0].get("value", [None, None])[1]
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if value == value else None


async def _first_prometheus_scalar(candidates: list[str]) -> dict[str, Any]:
    errors: list[str] = []
    for query in candidates:
        try:
            payload = await _cached_prometheus_get("/query", {"query": query})
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"Error de red consultando Prometheus: {e}") from e
        except httpx.HTTPStatusError as e:
            errors.append(f"{query}: {e.response.status_code}")
            continue

        value = _first_scalar(payload.get("data", {}).get("result", []) or [])
        if value is not None:
            return {"available": True, "value": value, "query": query, "errors": errors}

    return {"available": False, "value": None, "query": None, "errors": errors}


# =============================================================
# 🚨 Alertmanager — Realtime
# =============================================================


@router.get("/alerts/realtime")
async def get_alerts_realtime():
    """
    Devuelve la lista plana de alerts activas en Alertmanager.
    Este es el endpoint que consume el frontend (SystemAlerts, etc.).
    """
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            r = await client.get(ALERTMANAGER_ALERTS)
            r.raise_for_status()
            return r.json()
    except httpx.RequestError as e:
        logging.getLogger("zenthra").warning(
            "Alertmanager no disponible en /alerts/realtime: %s", e
        )
        return []
    except httpx.HTTPStatusError as e:
        logging.getLogger("zenthra").warning(
            "Alertmanager devolvio error en /alerts/realtime: %s - %s",
            e.response.status_code,
            e.response.text[:200],
        )
        return []


@router.get("/logs", response_model=RuntimeLogsResponse)
def get_runtime_logs(
    limit: int = Query(200, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
):
    """
    Devuelve logs reales del backend normalizados para la UI.

    Fuente principal:
      - logs/app.log
      - logs/app.log.1..5
      - logs/alerts_audit.log
    """
    return list_runtime_logs(limit=limit, severity=severity, search=search)


@router.get("/response-logs", response_model=list[ResponseLogRead])
def get_response_logs(
    limit: int = Query(100, ge=1, le=500),
    source: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """
    Devuelve evidencias persistidas de webhooks/acciones para la UI SOC.
    """
    query = db.query(ResponseLog)
    if source:
        query = query.filter(ResponseLog.source == source)
    if status:
        query = query.filter(ResponseLog.status == status)

    rows = query.order_by(ResponseLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": row.id,
            "timestamp": row.timestamp.isoformat(),
            "source": row.source,
            "source_ip": row.source_ip,
            "payload_hash": row.payload_hash,
            "payload_size": row.payload_size,
            "alert_count": row.alert_count,
            "status": row.status,
            "sample": row.sample,
        }
        for row in rows
    ]


# =============================================================
# 📬 Alertmanager — Webhook receiver (IP Whitelist + Auditoría)
# =============================================================


@hooks_router.post(
    "/hooks/alertmanager",
    dependencies=[Depends(_require_docker_network_source)],
    response_model=AlertmanagerHookResponse,
)
async def alertmanager_hook(request: Request, db: Session = Depends(get_db)):
    """
    Webhook receptor de Alertmanager (sin prefijo /monitoring).
    Protegido por IP Whitelist y persistido como evidencia forense.
    """
    try:
        payload = await request.json()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"JSON inválido: {e}") from e

    # Serializa estable y calcula SHA256 (evidencia forense)
    try:
        payload_str = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(
            status_code=500,
            detail=f"Error calculando hash: {e}",
        ) from e

    source_ip = request.client.host if request.client else "unknown"
    received = len(payload) if isinstance(payload, list) else 1

    # Escribe entrada de auditoría (no guarda el payload completo,
    # solo un sample para evitar logs enormes).
    AUDIT_LOG.info(
        "ALERT_HOOK ip=%s len=%d sha256=%s sample=%s",
        source_ip,
        len(payload_str),
        payload_hash,
        payload_str[:256],
    )

    response_log = ResponseLog(
        source="alertmanager",
        source_ip=source_ip,
        payload_hash=payload_hash,
        payload_size=len(payload_str),
        alert_count=received,
        status="received",
        sample=payload_str[:512],
    )
    try:
        db.add(response_log)
        db.commit()
        db.refresh(response_log)
    except Exception as e:  # noqa: BLE001
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error persistiendo webhook: {e}") from e

    return {
        "ok": True,
        "id": response_log.id,
        "hash": payload_hash,
        "received": received,
    }
