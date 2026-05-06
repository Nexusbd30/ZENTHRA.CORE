// =============================================================
// 🔔 SystemAlerts — ZENTHRA.CORE_SECURITY (v3.1 Debug+PromLink)
// =============================================================
// - Consume /monitoring/alerts/realtime (Alertmanager /api/v2/alerts)
// - Ordena por severidad
// - Reconstruye generatorURL con VITE_PROMETHEUS_PUBLIC_URL
// - Incluye DEBUG para ver en consola qué alertas llegan realmente
// =============================================================

import { useEffect, useState, useMemo } from "react";
import { getAlerts } from "@/api/nexusApi";

const OFFLINE_MSG = "No se puede conectar con el servidor.";
const PROM_PUBLIC_URL = (import.meta.env.VITE_PROMETHEUS_PUBLIC_URL || "").replace(
  /\/+$/,
  ""
);

// 🔢 Orden de severidad
const SEVERITY_ORDER = {
  critical: 0,
  high: 1,
  warning: 2,
  medium: 3,
  low: 4,
  info: 5,
  none: 6,
};

// 🎨 Pills de severidad
function pill(sev) {
  const base =
    "px-2 py-0.5 rounded-full text-xs font-semibold border capitalize";
  const map = {
    critical: `${base} border-red-400 text-red-300 bg-red-900/30`,
    high: `${base} border-orange-400 text-orange-300 bg-orange-900/30`,
    warning: `${base} border-amber-400 text-amber-300 bg-amber-900/30`,
    medium: `${base} border-yellow-400 text-yellow-300 bg-yellow-900/30`,
    low: `${base} border-lime-400 text-lime-300 bg-lime-900/30`,
    info: `${base} border-sky-400 text-sky-300 bg-sky-900/30`,
    none: `${base} border-slate-500 text-slate-300 bg-slate-800/50`,
  };
  return map[sev] || map.none;
}

// 🔗 Construir URL de Prometheus estable
function buildPrometheusURL(rawGeneratorURL, alertname) {
  if (!PROM_PUBLIC_URL) return null;

  // 1) Intentar usar el generatorURL que viene de Alertmanager
  if (rawGeneratorURL && rawGeneratorURL !== "false") {
    try {
      const u = new URL(rawGeneratorURL, PROM_PUBLIC_URL);
      return u.toString();
    } catch (err) {
      console.warn("[SystemAlerts] generatorURL inválida:", rawGeneratorURL, err);
    }
  }

  // 2) Fallback: construir una URL de /graph por alertname
  if (alertname) {
    try {
      const u = new URL(PROM_PUBLIC_URL);
      u.pathname = "/graph";
      u.searchParams.set("g0.expr", `ALERTS{alertname="${alertname}"}`);
      u.searchParams.set("g0.tab", "1");
      return u.toString();
    } catch (err) {
      console.warn("[SystemAlerts] Error construyendo URL fallback:", err);
    }
  }

  return null;
}

export default function SystemAlerts({
  autoRefreshMs = 10000,
  // 👇 Aumentamos el límite para no perder HighLatencyP95
  limit = 50,
}) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // 🔁 Fetch desde backend
  const fetchAlerts = async () => {
    try {
      setError(null);
      const res = await getAlerts();

      console.log("[SystemAlerts][DEBUG] raw alerts from backend:", res);
      if (Array.isArray(res)) {
        // Log rápido de los alertname para ver si está HighLatencyP95
        console.log(
          "[SystemAlerts][DEBUG] alertnames:",
          res.map((a) => a?.labels?.alertname)
        );
        setAlerts(res);
      } else {
        setAlerts([]);
      }
    } catch (e) {
      console.error("❌ Error obteniendo alertas:", e);
      setError(e?.message || "Error al obtener alertas");
    } finally {
      setLoading(false);
    }
  };

  // ⏱️ Refresco
  useEffect(() => {
    fetchAlerts();
    if (autoRefreshMs > 0) {
      const timer = setInterval(fetchAlerts, autoRefreshMs);
      return () => clearInterval(timer);
    }
  }, [autoRefreshMs]);

  // 🧩 Normalización + generatorURL
  const normalizedAlerts = useMemo(() => {
    const normalize = (a) => {
      const alertname = a?.labels?.alertname || "Alert";

      const sev =
        a?.labels?.severity?.toLowerCase?.() ||
        a?.labels?.severity_level?.toLowerCase?.() ||
        "none";

      const state =
        a?.status?.state?.toLowerCase?.() ||
        a?.state?.toLowerCase?.() ||
        "unknown";

      const rawGeneratorURL = a?.generatorURL || null;
      const generatorURL = buildPrometheusURL(rawGeneratorURL, alertname);

      return {
        id:
          a?.fingerprint ||
          `${alertname}-${a?.startsAt || Math.random()}`,
        name: alertname,
        severity: sev,
        state,
        summary: a?.annotations?.summary || "",
        description: a?.annotations?.description || "",
        startsAt: a?.startsAt || null,
        generatorURL,
      };
    };

    return alerts
      .map(normalize)
      .sort(
        (a, b) =>
          (SEVERITY_ORDER[a.severity] ?? 99) -
          (SEVERITY_ORDER[b.severity] ?? 99),
      )
      .slice(0, limit);
  }, [alerts, limit]);

  // 🧱 Render
  if (loading)
    return (
      <div className="text-sm text-slate-400 animate-pulse">
        Cargando alertas…
      </div>
    );

  if (error) {
    const isOffline = error.includes(OFFLINE_MSG);
    return (
      <div className="text-sm">
        {isOffline ? (
          <span className="text-slate-400">
            Backend offline — no se pueden obtener alertas ahora mismo.
          </span>
        ) : (
          <span className="text-red-400">
            Error al obtener alertas: {error}
          </span>
        )}
      </div>
    );
  }

  if (!normalizedAlerts.length)
    return (
      <div className="text-sm text-slate-400 italic">
        Sin alertas activas.
      </div>
    );

  return (
    <div className="space-y-3">
      {normalizedAlerts.map((a) => (
        <div
          key={a.id}
          className="border border-slate-700 rounded-xl p-4 bg-[#0f172a]/60 hover:bg-[#1e293b]/70 transition-colors duration-200 shadow-sm"
        >
          {/* Cabecera: nombre + severidad + estado */}
          <div className="flex items-center justify-between gap-2">
            <div className="font-semibold text-slate-100">
              {a.name || "Alerta"}
            </div>
            <div className="flex items-center gap-2">
              <span className={pill(a.severity)}>{a.severity}</span>
              <span
                className={`text-xs uppercase tracking-wide ${
                  a.state === "firing"
                    ? "text-red-400"
                    : a.state === "pending"
                    ? "text-amber-300"
                    : a.state === "resolved"
                    ? "text-emerald-300"
                    : "text-slate-400"
                }`}
              >
                {a.state}
              </span>
            </div>
          </div>

          {/* Resumen y descripción */}
          {a.summary && (
            <div className="text-sm mt-1 text-slate-200">{a.summary}</div>
          )}

          {a.description && (
            <div className="text-xs text-slate-400 mt-1">
              {a.description}
            </div>
          )}

          {/* Metadatos: inicio + link a Prometheus */}
          <div className="flex items-center justify-between mt-2 text-xs text-slate-500">
            <div>
              {a.startsAt && (
                <span>
                  Desde {new Date(a.startsAt).toLocaleString("es-ES")}
                </span>
              )}
            </div>
            {a.generatorURL ? (
              <a
                href={a.generatorURL}
                target="_blank"
                rel="noreferrer"
                className="text-blue-400 hover:underline"
              >
                Ver en Prometheus
              </a>
            ) : (
              <span className="text-slate-600 italic">
                Sin enlace a Prometheus
              </span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
