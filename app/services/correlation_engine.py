# =============================================================
# 🔥 ZENTHRA — Correlation Engine (v3.0 SIEM Incident Mode + DEDUPE Hardened)
# =============================================================
# ✅ SIEM Behavior:
#   - 1 fingerprint = 1 incidente OPEN mientras la alerta siga firing
#   - Si existen OPEN duplicados del pasado, se cierran como DEDUPED (auditable)
#   - Touch del incidente OPEN: updated_at, last_seen_at, occurrences, evidence
#   - Auto-resolve cuando deja de firing (con gracia)
#   - Reopen: si vuelve a firing en <24h, reabre un resolved reciente (evita spam)
#
# 📌 Nota:
#   - Para que /threats/?active=true devuelva 1 por fingerprint, ese endpoint
#     debe filtrar EXACTO por siem_metadata.status == "open".
# =============================================================

# mypy: ignore-errors
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.settings import settings
from app.models.threat_model import ThreatCategory, ThreatLevel, ThreatModel
from app.services.prometheus_client import PrometheusClient

# =============================================================
# ⚙️ Lifecycle / SIEM tuning
# =============================================================
AUTO_RESOLVE_ENABLED = True
AUTO_RESOLVE_GRACE_MINUTES = 2
AUTO_RESOLVE_LOOKBACK_HOURS = 48
REOPEN_WINDOW_HOURS = 24


# =============================================================
# ⚙️ RULESET — Reglas simples
# =============================================================
BASE_RULES = [
    {
        "rule_id": "BackendDown",
        "title": "Backend caído (BackendDown)",
        "description": "Prometheus detectó que zenthra-core no responde a /metrics (BackendDown firing).",
        "alert": "BackendDown",
        "level": ThreatLevel.critical,
        "category": ThreatCategory.availability,
        "score": 95,
        "target_service": "zenthra-core",
        "window": 10,  # legacy/compat (ya no controla dedupe)
    },
    {
        "rule_id": "HighErrorRate",
        "title": "Tasa elevada de errores 5xx (HighErrorRate)",
        "description": "La tasa de errores 5xx ha superado el umbral (HighErrorRate firing).",
        "alert": "HighErrorRate",
        "level": ThreatLevel.high,
        "category": ThreatCategory.performance,
        "score": 80,
        "target_service": "zenthra-core",
        "window": 10,
    },
    {
        "rule_id": "HighLatencyP95",
        "title": "Latencia p95 elevada (HighLatencyP95)",
        "description": "El percentil 95 de latencia supera el umbral (HighLatencyP95 firing).",
        "alert": "HighLatencyP95",
        "level": ThreatLevel.high,
        "category": ThreatCategory.availability,
        "score": 75,
        "target_service": "zenthra-core",
        "window": 10,
    },
    {
        "rule_id": "NetworkDDoS",
        "title": "Posible ataque DDoS / saturación de red (NetworkDDoS)",
        "description": "Patrón de tráfico compatible con DDoS (NetworkDDoS firing).",
        "alert": "NetworkDDoS",
        "level": ThreatLevel.critical,
        "category": ThreatCategory.network,
        "score": 97,
        "target_service": "network/edge",
        "window": 15,
    },
    {
        "rule_id": "NetworkRecon",
        "title": "Actividad de reconocimiento en red (NetworkRecon)",
        "description": "Patrón consistente con reconocimiento/escaneo (NetworkRecon firing).",
        "alert": "NetworkRecon",
        "level": ThreatLevel.high,
        "category": ThreatCategory.network,
        "score": 85,
        "target_service": "network/internal",
        "window": 30,
    },
    {
        "rule_id": "NetworkLateralMovement",
        "title": "Posible movimiento lateral (NetworkLateralMovement)",
        "description": "Tráfico compatible con movimiento lateral (NetworkLateralMovement firing).",
        "alert": "NetworkLateralMovement",
        "level": ThreatLevel.high,
        "category": ThreatCategory.network,
        "score": 90,
        "target_service": "network/lan",
        "window": 30,
    },
    {
        "rule_id": "VPNUnstable",
        "title": "Inestabilidad en túneles VPN (VPNUnstable)",
        "description": "Caídas/reconexiones anómalas VPN (VPNUnstable firing).",
        "alert": "VPNUnstable",
        "level": ThreatLevel.medium,
        "category": ThreatCategory.network,
        "score": 70,
        "target_service": "vpn/gateway",
        "window": 60,
    },
    {
        "rule_id": "DNSFailures",
        "title": "Fallos recurrentes de resolución DNS (DNSFailures)",
        "description": "Fallos recurrentes DNS (DNSFailures firing).",
        "alert": "DNSFailures",
        "level": ThreatLevel.medium,
        "category": ThreatCategory.network,
        "score": 65,
        "target_service": "dns/core",
        "window": 30,
    },
    # 🧪 LAB (se ignora por env)
    {
        "rule_id": "TestAlwaysFiring",
        "title": "Alerta de prueba Prometheus (TestAlwaysFiring)",
        "description": "Alerta de prueba generada para validar el motor.",
        "alert": "TestAlwaysFiring",
        "level": ThreatLevel.low,
        "category": ThreatCategory.availability,
        "score": 10,
        "target_service": "zenthra-core",
        "window": 5,
    },
    # 🖥️ Windows
    {
        "rule_id": "WindowsHighCPU",
        "title": "CPU alta en host Windows (WindowsHighCPU)",
        "description": "Uso elevado y sostenido de CPU en Windows (WindowsHighCPU firing).",
        "alert": "WindowsHighCPU",
        "level": ThreatLevel.high,
        "category": ThreatCategory.performance,
        "score": 75,
        "target_service": "windows-host",
        "window": 15,
    },
    {
        "rule_id": "WindowsDiskCAlmostFull",
        "title": "Riesgo de capacidad en disco C: (WindowsDiskCAlmostFull)",
        "description": "Disco C: casi lleno (WindowsDiskCAlmostFull firing).",
        "alert": "WindowsDiskCAlmostFull",
        "level": ThreatLevel.critical,
        "category": ThreatCategory.availability,
        "score": 85,
        "target_service": "windows-host/diskC",
        "window": 30,
    },
    # 🌐 Blackbox
    {
        "rule_id": "EndpointDownBlackbox",
        "title": "Endpoint externo caído (EndpointDownBlackbox)",
        "description": "Blackbox detecta endpoint no 2xx/no alcanzable (EndpointDownBlackbox firing).",
        "alert": "EndpointDownBlackbox",
        "level": ThreatLevel.medium,
        "category": ThreatCategory.availability,
        "score": 70,
        "target_service": "external-endpoint",
        "window": 10,
    },
]


# =============================================================
# 🔥 RULESET — Reglas compuestas
#   - Fingerprint compuesto estable: "composite|<rule_id>|<requires_sorted>"
# =============================================================
COMPOSITE_RULES = [
    {
        "rule_id": "BackendDegradation",
        "requires": ["HighLatencyP95", "HighErrorRate"],
        "title": "Degradación grave del backend (latencia + 5xx)",
        "description": "Latencia p95 + ratio 5xx simultáneo.",
        "level": ThreatLevel.critical,
        "category": ThreatCategory.availability,
        "score": 92,
        "target_service": "zenthra-core",
        "window": 15,
    },
    {
        "rule_id": "NetworkAttackActive",
        "requires": ["NetworkRecon", "NetworkLateralMovement"],
        "title": "Ataque de red activo (recon + movimiento lateral)",
        "description": "Recon + movimiento lateral simultáneo.",
        "level": ThreatLevel.critical,
        "category": ThreatCategory.network,
        "score": 95,
        "target_service": "network/internal",
        "window": 20,
    },
    {
        "rule_id": "AvailabilityCriticalIncident",
        "requires": ["BackendDown", "DNSFailures"],
        "title": "Incidente crítico de disponibilidad (BackendDown + DNS)",
        "description": "Backend caído + fallos DNS.",
        "level": ThreatLevel.critical,
        "category": ThreatCategory.availability,
        "score": 100,
        "target_service": "zenthra-core",
        "window": 10,
    },
    {
        "rule_id": "WindowsUnderPossibleDDoS",
        "requires": ["WindowsHighCPU", "NetworkDDoS"],
        "title": "Host Windows bajo posible DDoS (CPU alta + tráfico)",
        "description": "CPU alta en Windows + señales DDoS.",
        "level": ThreatLevel.critical,
        "category": ThreatCategory.network,
        "score": 96,
        "target_service": "windows-host",
        "window": 20,
    },
]


class CorrelationEngine:
    def __init__(self, prom_client: Optional[PrometheusClient] = None):
        self.prom = prom_client or PrometheusClient()

    # ---------------------------------------------------------
    # 🧬 fingerprint estable por alerta (vía PrometheusClient)
    # ---------------------------------------------------------
    def _fingerprint_from_alert(self, alert: dict, target_service: str | None = None) -> str:
        labels = alert.get("labels", {}) or {}
        return self.prom.build_fingerprint(labels, target_service=target_service)

    # ---------------------------------------------------------
    # 🧾 Evidencia SIEM segura (JSON portable)
    # ---------------------------------------------------------
    @staticmethod
    def _siem_meta_from_alert(alert_obj: Optional[dict]) -> dict:
        """
        Normaliza el objeto de alerta para guardarlo en JSON.
        """
        if not isinstance(alert_obj, dict):
            return {"labels": {}, "annotations": {}, "activeAt": None, "state": None, "value": None}
        return {
            "labels": alert_obj.get("labels", {}) or {},
            "annotations": alert_obj.get("annotations", {}) or {},
            "activeAt": alert_obj.get("activeAt"),
            "state": alert_obj.get("state"),
            "value": alert_obj.get("value"),
        }

    # ---------------------------------------------------------
    # ✅ Buscar incidente OPEN por fingerprint
    # (devuelve el OPEN más reciente)
    # ---------------------------------------------------------
    def _get_open_by_fingerprint(self, db: Session, fingerprint: str) -> Optional[ThreatModel]:
        rows = (
            db.query(ThreatModel)
            .filter(
                ThreatModel.fingerprint == fingerprint,
                ThreatModel.source == "prometheus/correlation",
            )
            .order_by(ThreatModel.updated_at.desc(), ThreatModel.created_at.desc())
            .limit(50)
            .all()
        )
        for t in rows:
            meta = t.siem_metadata if isinstance(t.siem_metadata, dict) else {}
            if meta.get("status") == "open":
                return t
        return None

    # ---------------------------------------------------------
    # 🧹 DEDUPE: cerrar OPEN duplicados dejando 1 solo OPEN
    # ---------------------------------------------------------
    def _dedupe_open_incidents(self, db: Session, fingerprint: str, *, keep_id: str, now: datetime) -> int:
        """
        Si existen múltiples incidentes OPEN con el mismo fingerprint (legacy),
        deja solo 1 OPEN (keep_id) y marca el resto como DEDUPED.

        ✅ Ventaja:
          - /threats?active=true puede devolver 1
          - se conserva histórico (audit trail) sin borrar nada
        """
        rows = (
            db.query(ThreatModel)
            .filter(
                ThreatModel.fingerprint == fingerprint,
                ThreatModel.source == "prometheus/correlation",
            )
            .order_by(ThreatModel.updated_at.desc(), ThreatModel.created_at.desc())
            .all()
        )

        deduped = 0
        for t in rows:
            if str(getattr(t, "id", "")) == str(keep_id):
                continue

            meta = t.siem_metadata if isinstance(t.siem_metadata, dict) else {}
            if meta.get("status") != "open":
                continue

            # Marcamos como deduped (NO open)
            meta["status"] = "deduped"
            meta["deduped_at"] = now.isoformat()
            meta["deduped_into"] = str(keep_id)
            meta["resolution_reason"] = "deduped_duplicate_open"

            t.siem_metadata = meta
            t.updated_at = now
            db.add(t)
            deduped += 1

        if deduped:
            db.commit()

        return deduped

    # ---------------------------------------------------------
    # ♻️ Reopen: si existe un resolved reciente, reabrirlo
    # ---------------------------------------------------------
    def _reopen_recent_resolved(
        self,
        db: Session,
        fingerprint: str,
        *,
        now: datetime,
        hours: int = REOPEN_WINDOW_HOURS,
    ) -> Optional[ThreatModel]:
        cutoff = now - timedelta(hours=int(hours))
        rows = (
            db.query(ThreatModel)
            .filter(
                ThreatModel.fingerprint == fingerprint,
                ThreatModel.source == "prometheus/correlation",
                ThreatModel.created_at >= cutoff,
            )
            .order_by(ThreatModel.updated_at.desc(), ThreatModel.created_at.desc())
            .limit(50)
            .all()
        )

        for t in rows:
            meta = t.siem_metadata if isinstance(t.siem_metadata, dict) else {}
            if meta.get("status") == "resolved":
                meta["status"] = "open"
                meta["reopened_at"] = now.isoformat()
                meta["last_seen_at"] = now.isoformat()
                if not meta.get("first_seen_at"):
                    meta["first_seen_at"] = (t.created_at.isoformat() if t.created_at else now.isoformat())
                t.siem_metadata = meta
                t.updated_at = now
                db.add(t)
                db.commit()
                db.refresh(t)
                return t

        return None

    # ---------------------------------------------------------
    # 🔁 Touch: actualizar incidente existente
    # ---------------------------------------------------------
    @staticmethod
    def _touch_existing(db: Session, t: ThreatModel, *, now: datetime, extra_meta: dict) -> ThreatModel:
        """
        Heartbeat SIEM:
          - status=open
          - last_seen_at
          - occurrences++
          - evidence actualizado
        """
        meta = t.siem_metadata if isinstance(t.siem_metadata, dict) else {}
        occurrences = int(meta.get("occurrences") or 1)

        meta.update(extra_meta or {})
        meta["status"] = "open"
        meta["last_seen_at"] = now.isoformat()
        meta["occurrences"] = occurrences + 1

        if not meta.get("first_seen_at"):
            meta["first_seen_at"] = (t.created_at.isoformat() if t.created_at else now.isoformat())

        t.siem_metadata = meta
        t.updated_at = now

        db.add(t)
        db.commit()
        db.refresh(t)
        return t

    # ---------------------------------------------------------
    # ✅ Crear incidente nuevo (OPEN)
    # ---------------------------------------------------------
    @staticmethod
    def _create_new(
        db: Session,
        *,
        title: str,
        description: str,
        level,
        category,
        score: int,
        target_service: str | None,
        fingerprint: str,
        base_meta: dict,
        now: datetime,
    ) -> ThreatModel:
        """
        Crea un incidente OPEN nuevo con siem_metadata mínimo.
        """
        meta = dict(base_meta or {})
        meta["status"] = "open"
        meta["first_seen_at"] = now.isoformat()
        meta["last_seen_at"] = now.isoformat()
        meta["occurrences"] = 1

        t = ThreatModel(
            title=title,
            source="prometheus/correlation",
            description=description,
            level=level,
            category=category,
            score=score,
            target_service=target_service,
            fingerprint=fingerprint,
            siem_metadata=meta,
        )
        db.add(t)
        db.commit()
        db.refresh(t)
        return t

    # ---------------------------------------------------------
    # ✅ Auto-resolve: si ya no está firing → status=resolved
    # ---------------------------------------------------------
    def _auto_resolve(self, db: Session, *, active_fingerprints: set[str], now: datetime) -> int:
        """
        Resuelve incidentes OPEN que ya no están firing.
        Solo mira lookback reciente para no tocar histórico.
        """
        if not AUTO_RESOLVE_ENABLED:
            return 0

        lookback = now - timedelta(hours=int(AUTO_RESOLVE_LOOKBACK_HOURS))
        grace_cutoff = now - timedelta(minutes=int(AUTO_RESOLVE_GRACE_MINUTES))

        candidates = (
            db.query(ThreatModel)
            .filter(ThreatModel.source == "prometheus/correlation")
            .filter(ThreatModel.created_at >= lookback)
            .all()
        )

        resolved_count = 0
        for t in candidates:
            fp = (t.fingerprint or "").strip()
            if not fp:
                continue

            meta = t.siem_metadata if isinstance(t.siem_metadata, dict) else {}
            if meta.get("status") != "open":
                continue

            # Si está activo, NO resolvemos (lo gestiona el touch)
            if fp in active_fingerprints:
                continue

            last_seen_at = meta.get("last_seen_at")
            try:
                last_seen_dt = datetime.fromisoformat(last_seen_at) if last_seen_at else None
            except Exception:
                last_seen_dt = None

            if last_seen_dt is None:
                last_seen_dt = t.updated_at or t.created_at or now

            # gracia anti-flapping
            if last_seen_dt > grace_cutoff:
                continue

            meta["status"] = "resolved"
            meta["resolved_at"] = now.isoformat()
            meta["resolution_reason"] = "auto_resolve_not_firing"
            t.siem_metadata = meta
            t.updated_at = now
            db.add(t)
            resolved_count += 1

        if resolved_count:
            db.commit()

        return resolved_count

    # ---------------------------------------------------------
    # 🎯 Correlación principal
    # ---------------------------------------------------------
    def run_correlation(self, db: Session) -> dict:
        created: List[ThreatModel] = []
        updated: List[ThreatModel] = []
        rules_triggered: List[str] = []

        now = datetime.utcnow()
        enable_lab = str(getattr(settings, "ZENTHRA_ENABLE_LAB_ALERTS", "false")).lower() == "true"

        # 1) Leer firing desde Prometheus
        firing = self.prom.get_firing_alerts()
        if not isinstance(firing, list):
            firing = []

        # 2) Indexar por alertname
        by_name: Dict[str, List[dict]] = {}
        for a in firing:
            if not isinstance(a, dict):
                continue
            labels = a.get("labels", {}) or {}
            name = labels.get("alertname")
            if not name:
                continue
            by_name.setdefault(name, []).append(a)

        fired_names = sorted(by_name.keys())
        fired_set = set(fired_names)

        # fingerprints activos en esta ejecución (para auto-resolve)
        active_fps: set[str] = set()

        # métricas SIEM útiles
        deduped_count = 0

        # -----------------------------------------------------
        # 3) Reglas simples (por fingerprint)
        # -----------------------------------------------------
        for rule in BASE_RULES:
            if rule["rule_id"] == "TestAlwaysFiring" and not enable_lab:
                continue

            alert_name = rule["alert"]
            alerts_for_name = by_name.get(alert_name, [])
            if not alerts_for_name:
                continue

            for alert_obj in alerts_for_name:
                fp = self._fingerprint_from_alert(alert_obj, target_service=rule.get("target_service"))
                active_fps.add(fp)

                # 3.1) Si existe OPEN => touch
                existing = self._get_open_by_fingerprint(db, fp)
                if not existing:
                    # 3.2) Si no existe OPEN, intentamos reabrir resolved reciente
                    existing = self._reopen_recent_resolved(db, fp, now=now, hours=REOPEN_WINDOW_HOURS)

                if existing:
                    touched = self._touch_existing(
                        db,
                        existing,
                        now=now,
                        extra_meta={"evidence": self._siem_meta_from_alert(alert_obj)},
                    )
                    updated.append(touched)

                    # 3.3) Limpieza: si había OPEN duplicados legacy, ciérralos
                    deduped_count += self._dedupe_open_incidents(db, fp, keep_id=str(touched.id), now=now)

                    if rule["rule_id"] not in rules_triggered:
                        rules_triggered.append(rule["rule_id"])
                    continue

                # 3.4) Si no hay nada, creamos incidente nuevo OPEN
                t = self._create_new(
                    db,
                    title=rule["title"],
                    description=rule["description"],
                    level=rule["level"],
                    category=rule["category"],
                    score=rule["score"],
                    target_service=rule["target_service"],
                    fingerprint=fp,
                    base_meta={"evidence": self._siem_meta_from_alert(alert_obj)},
                    now=now,
                )
                created.append(t)

                # 3.5) Por seguridad, dedupe también cuando el keeper es nuevo
                deduped_count += self._dedupe_open_incidents(db, fp, keep_id=str(t.id), now=now)

                if rule["rule_id"] not in rules_triggered:
                    rules_triggered.append(rule["rule_id"])

        # -----------------------------------------------------
        # 4) Reglas compuestas (1 fingerprint compuesto por regla)
        # -----------------------------------------------------
        for rule in COMPOSITE_RULES:
            requires = rule["requires"]
            if not all(r in fired_set for r in requires):
                continue

            composite_fp = "composite|" + rule["rule_id"] + "|" + "|".join(sorted(requires))
            active_fps.add(composite_fp)

            evidence = []
            for r in requires:
                sample = (by_name.get(r) or [None])[0]
                evidence.append(self._siem_meta_from_alert(sample))

            existing = self._get_open_by_fingerprint(db, composite_fp)
            if not existing:
                existing = self._reopen_recent_resolved(db, composite_fp, now=now, hours=REOPEN_WINDOW_HOURS)

            if existing:
                touched = self._touch_existing(
                    db,
                    existing,
                    now=now,
                    extra_meta={"requires": requires, "evidence": evidence},
                )
                updated.append(touched)

                deduped_count += self._dedupe_open_incidents(db, composite_fp, keep_id=str(touched.id), now=now)

                if rule["rule_id"] not in rules_triggered:
                    rules_triggered.append(rule["rule_id"])
                continue

            t = self._create_new(
                db,
                title=rule["title"],
                description=rule["description"],
                level=rule["level"],
                category=rule["category"],
                score=rule["score"],
                target_service=rule["target_service"],
                fingerprint=composite_fp,
                base_meta={"requires": requires, "evidence": evidence},
                now=now,
            )
            created.append(t)

            deduped_count += self._dedupe_open_incidents(db, composite_fp, keep_id=str(t.id), now=now)

            if rule["rule_id"] not in rules_triggered:
                rules_triggered.append(rule["rule_id"])

        # -----------------------------------------------------
        # 5) Auto-resolve: lo que ya no está firing
        # -----------------------------------------------------
        resolved_count = self._auto_resolve(db, active_fingerprints=active_fps, now=now)

        return {
            "created_count": len(created),
            "rules_triggered": rules_triggered,
            "fired_alerts": fired_names,
            "created_threats": created,  # el router lo serializa

            # métricas SIEM
            "updated_count": len(updated),
            "resolved_count": int(resolved_count),
            "deduped_count": int(deduped_count),

            "timestamp": now.isoformat(),
        }


# =============================================================
# 🧩 Instancia global
# =============================================================
correlation_engine = CorrelationEngine()
