# =============================================================
# 📡 PrometheusClient — ZENTHRA (v1.4 SIEM-Ready Stable)
# =============================================================
# ✅ Compatibilidad:
#   - query(expr) -> List[dict]
#   - has_result(expr) -> bool
#
# ✅ SIEM-ready:
#   - get_alerts(state="firing") -> List[dict] (NORMALIZADO)
#   - get_firing_alerts() -> List[dict]
#   - build_fingerprint(labels, target_service=None) -> str
# =============================================================

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import requests

from app.core.settings import settings

logger = logging.getLogger("zenthra.prometheus")


class PrometheusClient:
    def __init__(self, base_url: str | None = None, timeout_sec: Optional[float] = None) -> None:
        raw = base_url or getattr(settings, "PROMETHEUS_BASE", None) or "http://localhost:9090"
        self.base_url = raw.rstrip("/")

        self.timeout = float(
            timeout_sec if timeout_sec is not None else getattr(settings, "PROM_TIMEOUT_SEC", 8.0)
        )

        logger.info("[PrometheusClient] Base URL=%s timeout=%ss", self.base_url, self.timeout)

    # ---------------------------------------------------------
    # 🔍 Query instantánea
    # ---------------------------------------------------------
    def query(self, expr: str) -> List[dict]:
        url = f"{self.base_url}/api/v1/query"
        try:
            resp = requests.get(url, params={"query": expr}, timeout=self.timeout)
            resp.raise_for_status()
            data: Dict[str, Any] = resp.json()
        except Exception as e:
            logger.error("[PrometheusClient] Error query expr=%s -> %s", expr, e)
            return []

        if data.get("status") != "success":
            return []

        return (data.get("data", {}) or {}).get("result", []) or []

    # ---------------------------------------------------------
    # 🧠 Helper booleano
    # ---------------------------------------------------------
    def has_result(self, expr: str) -> bool:
        try:
            return len(self.query(expr)) > 0
        except Exception:
            return False

    # ---------------------------------------------------------
    # 🚨 Alertas activas vía Prometheus API (/api/v1/alerts)
    # ---------------------------------------------------------
    def get_alerts(self, state: Optional[str] = "firing") -> List[dict]:
        """
        Devuelve una LISTA de alertas normalizadas.

        state:
          - "firing" (por defecto)
          - "pending"
          - None -> devuelve todas

        Formato:
        [
          {
            "labels": {...},
            "annotations": {...},
            "state": "firing|pending",
            "activeAt": "...",
            "value": "...",
          },
          ...
        ]
        """
        url = f"{self.base_url}/api/v1/alerts"

        try:
            resp = requests.get(url, timeout=self.timeout)
            resp.raise_for_status()
            payload: Dict[str, Any] = resp.json()
        except Exception as e:
            logger.error("[PrometheusClient] Error /api/v1/alerts -> %s", e)
            return []

        if not isinstance(payload, dict) or payload.get("status") != "success":
            return []

        data = payload.get("data", {})
        if not isinstance(data, dict):
            return []

        raw_alerts = data.get("alerts", [])
        if not isinstance(raw_alerts, list):
            return []

        normalized: List[dict] = []
        for a in raw_alerts:
            if not isinstance(a, dict):
                continue
            normalized.append(
                {
                    "labels": a.get("labels") or {},
                    "annotations": a.get("annotations") or {},
                    "state": a.get("state"),
                    "activeAt": a.get("activeAt"),
                    "value": a.get("value"),
                }
            )

        if state:
            normalized = [x for x in normalized if x.get("state") == state]

        return normalized

    def get_firing_alerts(self) -> List[dict]:
        return self.get_alerts(state="firing")

    # ---------------------------------------------------------
    # 🧬 Fingerprint helper
    # ---------------------------------------------------------
    @staticmethod
    def build_fingerprint(labels: Dict[str, Any], target_service: str | None = None) -> str:
        alertname = str(labels.get("alertname", "")).strip()
        instance = str(labels.get("instance", "")).strip()
        job = str(labels.get("job", "")).strip()
        service = str(labels.get("service", "")).strip()

        # prioridad: label service > target_service (fallback)
        svc = service or (target_service or "").strip()

        base = f"{alertname}|{instance}|{job}"
        return f"{base}|{svc}" if svc else base
